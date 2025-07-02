import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { authenticateToken } from './authMiddleware'

// Mock jsonwebtoken
vi.mock('jsonwebtoken', () => ({
  default: {
    verify: vi.fn(),
  },
}))

describe('authMiddleware', () => {
  let req: Partial<Request>
  let res: Partial<Response>
  let next: NextFunction

  beforeEach(() => {
    req = {}
    res = {
      sendStatus: vi.fn(),
    }
    next = vi.fn()
    process.env.JWT_SECRET = 'test_secret'
  })

  it('should return 401 if no token is provided', () => {
    req.headers = {}
    authenticateToken(req as Request, res as Response, next)
    expect(res.sendStatus).toHaveBeenCalledWith(401)
    expect(next).not.toHaveBeenCalled()
  })

  it('should return 403 if token is "null" string', () => {
    req.headers = { authorization: 'Bearer null' }
    ;(jwt.verify as vi.Mock).mockImplementation((token, secret, callback) => {
      callback(new Error('Invalid token'), undefined)
    })
    authenticateToken(req as Request, res as Response, next)
    expect(jwt.verify).toHaveBeenCalledWith('null', 'test_secret', expect.any(Function))
    expect(res.sendStatus).toHaveBeenCalledWith(403)
    expect(next).not.toHaveBeenCalled()
  })

  it('should return 403 if token is invalid', () => {
    req.headers = { authorization: 'Bearer invalid_token' }
    ;(jwt.verify as vi.Mock).mockImplementation((token, secret, callback) => {
      callback(new Error('Invalid token'), undefined)
    })

    authenticateToken(req as Request, res as Response, next)

    expect(jwt.verify).toHaveBeenCalledWith('invalid_token', 'test_secret', expect.any(Function))
    expect(res.sendStatus).toHaveBeenCalledWith(403)
    expect(next).not.toHaveBeenCalled()
  })

  it('should set userId and call next if token is valid', () => {
    const mockUser = { userId: '123' }
    req.headers = { authorization: 'Bearer valid_token' }
    ;(jwt.verify as vi.Mock).mockImplementation((token, secret, callback) => {
      callback(null, mockUser)
    })

    authenticateToken(req as Request, res as Response, next)

    expect(jwt.verify).toHaveBeenCalledWith('valid_token', 'test_secret', expect.any(Function))
    expect((req as any).userId).toBe(mockUser.userId)
    expect(next).toHaveBeenCalled()
    expect(res.sendStatus).not.toHaveBeenCalled()
  })
})
