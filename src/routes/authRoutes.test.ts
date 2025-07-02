import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest'

import * as authController from '../controllers/authController'
import * as validateRequest from '../middlewares/validateRequest'
import * as authSchemas from '../schemas/authSchemas'

const mockRouterInstance = {
  post: vi.fn(),
  get: vi.fn(),
}

vi.mock('express', () => ({
  Router: vi.fn(() => mockRouterInstance), // Always return the same mockRouterInstance
}))

let authRoutes: any

describe('authRoutes', () => {
  beforeAll(async () => {
    const module = await import('./authRoutes')
    authRoutes = module.default
  })

  beforeEach(() => {
    mockRouterInstance.post.mockClear()
    mockRouterInstance.get.mockClear()
  })

  it('should set up auth routes correctly', () => {
    expect(mockRouterInstance.post).toHaveBeenCalledWith(
      '/register',
      validateRequest.validate(authSchemas.registerSchema),
      authController.register,
    )
    expect(mockRouterInstance.post).toHaveBeenCalledWith(
      '/login',
      validateRequest.validate(authSchemas.loginSchema),
      authController.login,
    )
    expect(mockRouterInstance.post).toHaveBeenCalledWith(
      '/forgot-password',
      validateRequest.validate(authSchemas.forgotPasswordSchema),
      authController.forgotPassword,
    )
    expect(mockRouterInstance.post).toHaveBeenCalledWith(
      '/reset-password',
      validateRequest.validate(authSchemas.resetPasswordSchema),
      authController.resetPassword,
    )
    expect(mockRouterInstance.get).toHaveBeenCalledWith(
      '/verify/:token',
      authController.verifyEmail,
    )
    expect(mockRouterInstance.post).toHaveBeenCalledWith('/logout', authController.logout)
  })
})
