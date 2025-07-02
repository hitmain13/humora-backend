import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as authService from './authService';
import prisma from '../config/prisma';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Mock prisma
vi.mock('../config/prisma', () => ({
  default: {
    user: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
    },
  },
}));

// Mock bcryptjs
vi.mock('bcryptjs', () => ({
  default: {
    hash: vi.fn(),
    compare: vi.fn(),
  },
}));

// Mock jsonwebtoken
vi.mock('jsonwebtoken', () => ({
  default: {
    sign: vi.fn(),
    verify: vi.fn(),
  },
}));

describe('authService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.JWT_SECRET = 'test_secret'; // Set a test secret for JWT
  });

  afterEach(() => {
    delete process.env.JWT_SECRET; // Clean up the test secret
  });

  describe('registerUser', () => {
    it('should register a user successfully', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      const hashedPassword = 'hashed_password';
      const verificationToken = 'mock_verification_token';
      const mockUser = { id: '1', email, password: hashedPassword, emailVerificationToken: verificationToken };

      vi.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword);
      vi.spyOn(jwt, 'sign').mockReturnValue(verificationToken);
      vi.spyOn(prisma.user, 'create').mockResolvedValue(mockUser);

      const user = await authService.registerUser(email, password);

      expect(bcrypt.hash).toHaveBeenCalledWith(password, 10);
      expect(jwt.sign).toHaveBeenCalledWith({ email }, 'test_secret', { expiresIn: '1h' });
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          email,
          password: hashedPassword,
          emailVerificationToken: verificationToken,
          emailVerificationTokenExpiresAt: expect.any(Date),
        },
      });
      expect(user).toEqual(mockUser);
    });

    it('should throw an error if user creation fails', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      const hashedPassword = 'hashed_password';

      vi.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword);
      vi.spyOn(jwt, 'sign').mockReturnValue('mock_verification_token');
      vi.spyOn(prisma.user, 'create').mockRejectedValue(new Error('Database error'));

      await expect(authService.registerUser(email, password)).rejects.toThrow('Database error');
      expect(bcrypt.hash).toHaveBeenCalledWith(password, 10);
      expect(jwt.sign).toHaveBeenCalledWith({ email }, 'test_secret', { expiresIn: '1h' });
      expect(prisma.user.create).toHaveBeenCalled();
    });
  });

  describe('loginUser', () => {
    it('should login a user successfully', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      const mockUser = { id: '1', email, password: 'hashed_password', isVerified: true };
      const mockToken = 'mock_jwt_token';

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser);
      vi.spyOn(bcrypt, 'compare').mockResolvedValue(true);
      vi.spyOn(jwt, 'sign').mockReturnValue(mockToken);

      const token = await authService.loginUser(email, password);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password);
      expect(jwt.sign).toHaveBeenCalledWith({ userId: mockUser.id }, 'test_secret', { expiresIn: '1h' });
      expect(token).toBe(mockToken);
    });

    it('should throw an error if user not found', async () => {
      const email = 'test@example.com';
      const password = 'password123';

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(null);

      await expect(authService.loginUser(email, password)).rejects.toThrow('Invalid credentials');
      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } });
      expect(bcrypt.compare).not.toHaveBeenCalled();
      expect(jwt.sign).not.toHaveBeenCalled();
    });

    it('should throw an error if password does not match', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      const mockUser = { id: '1', email, password: 'hashed_password', isVerified: true };

      vi.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser);
      vi.spyOn(bcrypt, 'compare').mockResolvedValue(false);

      await expect(authService.loginUser(email, password)).rejects.toThrow('Invalid credentials');
      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email } });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password);
      expect(jwt.sign).not.toHaveBeenCalled();
    });
  });
});