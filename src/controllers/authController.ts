import { Request, Response } from 'express';
import { registerUser, loginUser, sendPasswordResetLink, resetUserPassword, verifyUserEmail } from '../services/authService';

export const register = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  try {
    const user = await registerUser(email, password);
    res.status(201).json({ message: 'User registered successfully. Please check your email for verification.', userId: user.id });
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(409).json({ message: 'Email already registered' });
    }
    res.status(500).json({ message: error.message || 'Internal server error' });
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  try {
    const token = await loginUser(email, password);
    res.status(200).json({ token });
  } catch (error: any) {
    res.status(400).json({ message: error.message || 'Invalid credentials' });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  try {
    await sendPasswordResetLink(email);
    res.status(200).json({ message: 'Password reset link sent to your email' });
  } catch (error: any) {
    res.status(404).json({ message: error.message || 'User not found' });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  const { token, newPassword } = req.body;
  try {
    await resetUserPassword(token, newPassword);
    res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (error: any) {
    res.status(400).json({ message: error.message || 'Invalid or expired token' });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.params;
  try {
    await verifyUserEmail(token);
    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error: any) {
    res.status(400).json({ message: error.message || 'Invalid or expired verification token' });
  }
};