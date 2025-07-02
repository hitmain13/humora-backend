import { Request, Response } from 'express'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import * as authService from '../services/authService'
import {
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyEmail,
  logout,
} from './authController'

describe('authController', () => {
  let req: Partial<Request>
  let res: Partial<Response>

  beforeEach(() => {
    req = {}
    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    }
  })

  it('should return a success message on logout', () => {
    logout(req as Request, res as Response)
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith({ message: 'Logged out successfully' })
  })

  describe('register', () => {
    it('should register a user successfully', async () => {
      const mockUser = { id: '123', email: 'test@example.com' }
      vi.spyOn(authService, 'registerUser').mockResolvedValue(mockUser)

      req.body = { email: 'test@example.com', password: 'password123' }
      await register(req as Request, res as Response)

      expect(authService.registerUser).toHaveBeenCalledWith('test@example.com', 'password123')
      expect(res.status).toHaveBeenCalledWith(201)
      expect(res.json).toHaveBeenCalledWith({
        message: 'User registered successfully. Please check your email for verification.',
        userId: mockUser.id,
      })
    })

    it('should handle email already registered error', async () => {
      const error = new Error('Email already registered')
      ;(error as any).code = 'P2002'
      vi.spyOn(authService, 'registerUser').mockRejectedValue(error)

      req.body = { email: 'test@example.com', password: 'password123' }
      await register(req as Request, res as Response)

      expect(authService.registerUser).toHaveBeenCalledWith('test@example.com', 'password123')
      expect(res.status).toHaveBeenCalledWith(409)
      expect(res.json).toHaveBeenCalledWith({ message: 'Email already registered' })
    })

    it('should handle generic registration error', async () => {
      vi.spyOn(authService, 'registerUser').mockRejectedValue(new Error('Something went wrong'))

      req.body = { email: 'test@example.com', password: 'password123' }
      await register(req as Request, res as Response)

      expect(authService.registerUser).toHaveBeenCalledWith('test@example.com', 'password123')
      expect(res.status).toHaveBeenCalledWith(500)
      expect(res.json).toHaveBeenCalledWith({ message: 'Something went wrong' })
    })
  })

  describe('login', () => {
    it('should login a user successfully', async () => {
      const mockToken = 'mock-jwt-token'
      vi.spyOn(authService, 'loginUser').mockResolvedValue(mockToken)

      req.body = { email: 'test@example.com', password: 'password123' }
      await login(req as Request, res as Response)

      expect(authService.loginUser).toHaveBeenCalledWith('test@example.com', 'password123')
      expect(res.status).toHaveBeenCalledWith(200)
      expect(res.json).toHaveBeenCalledWith({ token: mockToken })
    })

    it('should handle invalid credentials on login', async () => {
      vi.spyOn(authService, 'loginUser').mockRejectedValue(new Error('Invalid credentials'))

      req.body = { email: 'test@example.com', password: 'password123' }
      await login(req as Request, res as Response)

      expect(authService.loginUser).toHaveBeenCalledWith('test@example.com', 'password123')
      expect(res.status).toHaveBeenCalledWith(400)
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid credentials' })
    })
  })

  describe('forgotPassword', () => {
    it('should send password reset link successfully', async () => {
      vi.spyOn(authService, 'sendPasswordResetLink').mockResolvedValue(undefined)

      req.body = { email: 'test@example.com' }
      await forgotPassword(req as Request, res as Response)

      expect(authService.sendPasswordResetLink).toHaveBeenCalledWith('test@example.com')
      expect(res.status).toHaveBeenCalledWith(200)
      expect(res.json).toHaveBeenCalledWith({ message: 'Password reset link sent to your email' })
    })

    it('should handle user not found on forgot password', async () => {
      vi.spyOn(authService, 'sendPasswordResetLink').mockRejectedValue(new Error('User not found'))

      req.body = { email: 'test@example.com' }
      await forgotPassword(req as Request, res as Response)

      expect(authService.sendPasswordResetLink).toHaveBeenCalledWith('test@example.com')
      expect(res.status).toHaveBeenCalledWith(404)
      expect(res.json).toHaveBeenCalledWith({ message: 'User not found' })
    })
  })

  describe('resetPassword', () => {
    it('should reset password successfully', async () => {
      vi.spyOn(authService, 'resetUserPassword').mockResolvedValue(undefined)

      req.body = { token: 'mock-token', newPassword: 'newpassword123' }
      await resetPassword(req as Request, res as Response)

      expect(authService.resetUserPassword).toHaveBeenCalledWith('mock-token', 'newpassword123')
      expect(res.status).toHaveBeenCalledWith(200)
      expect(res.json).toHaveBeenCalledWith({ message: 'Password has been reset successfully' })
    })

    it('should handle invalid or expired token on reset password', async () => {
      vi.spyOn(authService, 'resetUserPassword').mockRejectedValue(
        new Error('Invalid or expired token'),
      )

      req.body = { token: 'invalid-token', newPassword: 'newpassword123' }
      await resetPassword(req as Request, res as Response)

      expect(authService.resetUserPassword).toHaveBeenCalledWith('invalid-token', 'newpassword123')
      expect(res.status).toHaveBeenCalledWith(400)
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid or expired token' })
    })
  })

  describe('verifyEmail', () => {
    it('should verify email successfully', async () => {
      req.params = { token: 'mock-verification-token' }
      vi.spyOn(authService, 'verifyUserEmail').mockResolvedValue(undefined)

      await verifyEmail(req as Request, res as Response)

      expect(authService.verifyUserEmail).toHaveBeenCalledWith('mock-verification-token')
      expect(res.status).toHaveBeenCalledWith(200)
      expect(res.json).toHaveBeenCalledWith({ message: 'Email verified successfully' })
    })

    it('should handle invalid or expired verification token', async () => {
      req.params = { token: 'invalid-verification-token' }
      vi.spyOn(authService, 'verifyUserEmail').mockRejectedValue(
        new Error('Invalid or expired verification token'),
      )

      await verifyEmail(req as Request, res as Response)

      expect(authService.verifyUserEmail).toHaveBeenCalledWith('invalid-verification-token')
      expect(res.status).toHaveBeenCalledWith(400)
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid or expired verification token' })
    })
  })
})
