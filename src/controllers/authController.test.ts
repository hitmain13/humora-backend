import { describe, it, expect, vi } from 'vitest';
import { Request, Response } from 'express';
import { logout } from './authController';

describe('authController', () => {
  it('should return a success message on logout', () => {
    const req = {} as Request;
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    } as unknown as Response;

    logout(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ message: 'Logged out successfully' });
  });
});