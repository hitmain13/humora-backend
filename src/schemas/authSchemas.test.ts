import { describe, it, expect } from 'vitest'

import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from './authSchemas'

describe('authSchemas', () => {
  describe('registerSchema', () => {
    it('should validate a valid registration payload', () => {
      const payload = { email: 'test@example.com', password: 'password123' }
      expect(() => registerSchema.parse(payload)).not.toThrow()
    })

    it('should throw an error for invalid email in registration', () => {
      const payload = { email: 'invalid-email', password: 'password123' }
      expect(() => registerSchema.parse(payload)).toThrow('Invalid email address')
    })

    it('should throw an error for short password in registration', () => {
      const payload = { email: 'test@example.com', password: 'short' }
      expect(() => registerSchema.parse(payload)).toThrow(
        'Password must be at least 6 characters long',
      )
    })

    it('should throw an error for missing email in registration', () => {
      const payload = { password: 'password123' }
      expect(() => registerSchema.parse(payload)).toThrow()
    })

    it('should throw an error for missing password in registration', () => {
      const payload = { email: 'test@example.com' }
      expect(() => registerSchema.parse(payload)).toThrow()
    })
  })

  describe('loginSchema', () => {
    it('should validate a valid login payload', () => {
      const payload = { email: 'test@example.com', password: 'password123' }
      expect(() => loginSchema.parse(payload)).not.toThrow()
    })

    it('should throw an error for invalid email in login', () => {
      const payload = { email: 'invalid-email', password: 'password123' }
      expect(() => loginSchema.parse(payload)).toThrow('Invalid email address')
    })

    it('should throw an error for short password in login', () => {
      const payload = { email: 'test@example.com', password: 'short' }
      expect(() => loginSchema.parse(payload)).toThrow(
        'Password must be at least 6 characters long',
      )
    })
  })

  describe('forgotPasswordSchema', () => {
    it('should validate a valid forgot password payload', () => {
      const payload = { email: 'test@example.com' }
      expect(() => forgotPasswordSchema.parse(payload)).not.toThrow()
    })

    it('should throw an error for invalid email in forgot password', () => {
      const payload = { email: 'invalid-email' }
      expect(() => forgotPasswordSchema.parse(payload)).toThrow('Invalid email address')
    })
  })

  describe('resetPasswordSchema', () => {
    it('should validate a valid reset password payload', () => {
      const payload = { token: 'some_token', newPassword: 'newpassword123' }
      expect(() => resetPasswordSchema.parse(payload)).not.toThrow()
    })

    it('should throw an error for missing token in reset password', () => {
      const payload = { newPassword: 'newpassword123' }
      expect(() => resetPasswordSchema.parse(payload)).toThrow('Required')
    })

    it('should throw an error for short new password in reset password', () => {
      const payload = { token: 'some_token', newPassword: 'short' }
      expect(() => resetPasswordSchema.parse(payload)).toThrow(
        'New password must be at least 6 characters long',
      )
    })
  })
})
