import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import prisma from '../config/prisma'
import * as authService from './authService'

describe('authService', () => {
  describe('registerUser', () => {
    it('should register a user successfully', async () => {
      const email = 'test@example.com'
      const password = 'password123'
      const hashedPassword = 'hashed_password'
      const verificationToken = 'mock_verification_token'
      const mockUser = {
        id: '1',
        email,
        password: hashedPassword,
        emailVerificationToken: verificationToken,
      }

      vi.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword)
      vi.spyOn(jwt, 'sign').mockReturnValue(verificationToken)
      vi.spyOn(prisma.user, 'create').mockResolvedValue(mockUser)

      const user = await authService.registerUser(email, password)

      expect(bcrypt.hash).toHaveBeenCalledWith(password, 10)
      expect(jwt.sign).toHaveBeenCalledWith({ email }, 'test_secret', {
        expiresIn: '1h',
      })
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          email,
          password: hashedPassword,
          emailVerificationToken: verificationToken,
          emailVerificationTokenExpiresAt: expect.any(Date),
        },
      })
      expect(user).toEqual(mockUser)
    })

    it('should throw an error if user creation fails', async () => {
      const email = 'test@example.com'
      const password = 'password123'
      const hashedPassword = 'hashed_password'

      vi.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword)
      vi.spyOn(jwt, 'sign').mockReturnValue('mock_verification_token')
      vi.spyOn(prisma.user, 'create').mockRejectedValue(new Error('Database error'))

      await expect(authService.registerUser(email, password)).rejects.toThrow('Database error')
      expect(bcrypt.hash).toHaveBeenCalledWith(password, 10)
      expect(jwt.sign).toHaveBeenCalledWith({ email }, 'test_secret', {
        expiresIn: '1h',
      })
      expect(prisma.user.create).toHaveBeenCalled()
    })
  })

  describe('loginUser', () => {
    it('should login a user successfully', async () => {
      const email = 'test@example.com'
      const password = 'password123'
      const mockUser = {
        id: '1',
        email,
        password: 'hashed_password',
        isVerified: true,
      }
      const mockToken = 'mock_jwt_token'

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser)
      vi.spyOn(bcrypt, 'compare').mockResolvedValue(true)
      vi.spyOn(jwt, 'sign').mockReturnValue(mockToken)

      const token = await authService.loginUser(email, password)

      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } })
      expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password)
      expect(jwt.sign).toHaveBeenCalledWith({ userId: mockUser.id }, 'test_secret', {
        expiresIn: '1h',
      })
      expect(token).toBe(mockToken)
    })

    it('should throw an error if user not found', async () => {
      const email = 'test@example.com'
      const password = 'password123'

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(null)

      await expect(authService.loginUser(email, password)).rejects.toThrow('Invalid credentials')
      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } })
      expect(bcrypt.compare).not.toHaveBeenCalled()
      expect(jwt.sign).not.toHaveBeenCalled()
    })

    it('should throw an error if password does not match', async () => {
      const email = 'test@example.com'
      const password = 'password123'
      const mockUser = {
        id: '1',
        email,
        password: 'hashed_password',
        isVerified: true,
      }

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser)
      vi.spyOn(bcrypt, 'compare').mockResolvedValue(false)

      await expect(authService.loginUser(email, password)).rejects.toThrow('Invalid credentials')
      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } })
      expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password)
      expect(jwt.sign).not.toHaveBeenCalled()
    })
  })

  describe('sendPasswordResetLink', () => {
    it('should send password reset link successfully', async () => {
      const email = 'test@example.com'
      const mockUser = { id: '1', email }
      const resetToken = 'mock_reset_token'

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser)
      vi.spyOn(jwt, 'sign').mockReturnValue(resetToken)

      const result = await authService.sendPasswordResetLink(email)

      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } })
      expect(jwt.sign).toHaveBeenCalledWith({ userId: mockUser.id }, 'test_secret', {
        expiresIn: '15m',
      })
      expect(result).toBe(resetToken)
    })

    it('should throw an error if user not found', async () => {
      const email = 'test@example.com'

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(null)

      await expect(authService.sendPasswordResetLink(email)).rejects.toThrow('User not found')
      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } })
      expect(jwt.sign).not.toHaveBeenCalled()
    })
  })

  describe('resetUserPassword', () => {
    it('should reset user password successfully', async () => {
      const token = 'mock_token'
      const newPassword = 'new_password'
      const decoded = { userId: '1' }
      const mockUser = { id: '1', email: 'test@example.com' }
      const hashedPassword = 'hashed_new_password'

      vi.spyOn(jwt, 'verify').mockReturnValue(decoded)
      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser)
      vi.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword)
      vi.spyOn(prisma.user, 'update').mockResolvedValue(mockUser)

      await authService.resetUserPassword(token, newPassword)

      expect(jwt.verify).toHaveBeenCalledWith(token, 'test_secret')
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: decoded.userId },
      })
      expect(bcrypt.hash).toHaveBeenCalledWith(newPassword, 10)
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { password: hashedPassword },
      })
    })

    it('should throw an error if token is invalid or expired', async () => {
      const token = 'invalid_token'
      const newPassword = 'new_password'

      vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new Error('Invalid token')
      })

      await expect(authService.resetUserPassword(token, newPassword)).rejects.toThrow(
        'Invalid token',
      )
      expect(jwt.verify).toHaveBeenCalledWith(token, 'test_secret')
      expect(prisma.user.findUnique).not.toHaveBeenCalled()
      expect(bcrypt.hash).not.toHaveBeenCalled()
      expect(prisma.user.update).not.toHaveBeenCalled()
    })

    it('should throw an error if user not found after token verification', async () => {
      const token = 'mock_token'
      const newPassword = 'new_password'
      const decoded = { userId: '1' }

      vi.spyOn(jwt, 'verify').mockReturnValue(decoded)
      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(null)

      await expect(authService.resetUserPassword(token, newPassword)).rejects.toThrow(
        'Invalid or expired token',
      )
      expect(jwt.verify).toHaveBeenCalledWith(token, 'test_secret')
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: decoded.userId },
      })
      expect(bcrypt.hash).not.toHaveBeenCalled()
      expect(prisma.user.update).not.toHaveBeenCalled()
    })
  })

  describe('verifyUserEmail', () => {
    it('should verify user email successfully', async () => {
      const token = 'mock_verification_token'
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        emailVerificationToken: token,
        emailVerificationTokenExpiresAt: new Date(Date.now() + 3600000),
      }

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser)
      vi.spyOn(prisma.user, 'update').mockResolvedValue({
        ...mockUser,
        isVerified: true,
        emailVerificationToken: null,
        emailVerificationTokenExpiresAt: null,
      })

      await authService.verifyUserEmail(token)

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { emailVerificationToken: token },
      })
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: {
          isVerified: true,
          emailVerificationToken: null,
          emailVerificationTokenExpiresAt: null,
        },
      })
    })

    it('should throw an error if verification token is invalid or expired', async () => {
      const token = 'invalid_token'

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(null)

      await expect(authService.verifyUserEmail(token)).rejects.toThrow(
        'Invalid or expired verification token',
      )
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { emailVerificationToken: token },
      })
      expect(prisma.user.update).not.toHaveBeenCalled()
    })

    it('should throw an error if verification token has expired', async () => {
      const token = 'expired_token'
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        emailVerificationToken: token,
        emailVerificationTokenExpiresAt: new Date(Date.now() - 3600000),
      }

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser)

      await expect(authService.verifyUserEmail(token)).rejects.toThrow(
        'Verification token has expired',
      )
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { emailVerificationToken: token },
      })
      expect(prisma.user.update).not.toHaveBeenCalled()
    })
  })
  beforeEach(() => {
    vi.clearAllMocks()
    process.env.JWT_SECRET = 'test_secret'
  })

  afterEach(() => {
    delete process.env.JWT_SECRET
  })
})

vi.mock('../config/prisma', () => ({
  default: {
    user: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
    },
  },
}))

vi.mock('bcryptjs', () => ({
  default: {
    hash: vi.fn(),
    compare: vi.fn(),
  },
}))

vi.mock('jsonwebtoken', () => ({
  default: {
    sign: vi.fn(),
    verify: vi.fn(),
  },
}))
