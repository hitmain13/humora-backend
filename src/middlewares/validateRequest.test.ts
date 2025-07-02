import { Request, Response, NextFunction } from 'express'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { z } from 'zod'

import { validate } from './validateRequest'

describe('validateRequest middleware', () => {
  let req: Partial<Request>
  let res: Partial<Response>
  let next: NextFunction

  beforeEach(() => {
    req = {}
    res = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    }
    next = vi.fn()
  })

  it('should call next if validation succeeds', () => {
    const mockSchema = z.object({
      body: z.object({
        name: z.string(),
      }),
    })

    req.body = { name: 'test' }

    validate(mockSchema)(req as Request, res as Response, next)

    expect(next).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
    expect(res.send).not.toHaveBeenCalled()
  })

  it('should return 400 and errors if validation fails', () => {
    const mockSchema = z.object({
      body: z.object({
        name: z.string(),
      }),
    })

    req.body = { name: 123 } // Invalid type

    validate(mockSchema)(req as Request, res as Response, next)

    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.send).toHaveBeenCalledWith(expect.any(Array))
    expect(res.send.mock.calls[0][0][0]).toHaveProperty('message')
  })

  it('should validate query parameters', () => {
    const mockSchema = z.object({
      query: z.object({
        id: z.string(),
      }),
    })

    req.query = { id: '123' }

    validate(mockSchema)(req as Request, res as Response, next)

    expect(next).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
    expect(res.send).not.toHaveBeenCalled()
  })

  it('should validate params', () => {
    const mockSchema = z.object({
      params: z.object({
        userId: z.string(),
      }),
    })

    req.params = { userId: 'abc' }

    validate(mockSchema)(req as Request, res as Response, next)

    expect(next).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
    expect(res.send).not.toHaveBeenCalled()
  })
})
