import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import prisma from '../config/prisma'

export const register = async (req: Request, res: Response) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' })
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10)
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET!, { expiresIn: '1h' });

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        emailVerificationToken: verificationToken,
        emailVerificationTokenExpiresAt: new Date(Date.now() + 3600000), // 1 hour expiry
      },
    });

    console.log(`Verification token for ${email}: ${verificationToken}`);

    res.status(201).json({ message: 'User registered successfully. Please check your email for verification.', userId: user.id });
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(409).json({ message: 'Email already registered' })
    }
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' })
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } })

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' })
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '1h' })

    res.status(200).json({ token })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body

  if (!email) {
    return res.status(400).json({ message: 'Email is required' })
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } })

    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '15m' })

    console.log(`Password reset token for ${email}: ${resetToken}`)

    res.status(200).json({ message: 'Password reset link sent to your email' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const resetPassword = async (req: Request, res: Response) => {
  const { token, newPassword } = req.body

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' })
  }

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!) 

    const user = await prisma.user.findUnique({ where: { id: decoded.userId } })

    if (!user) {
      return res.status(404).json({ message: 'Invalid or expired token' })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10)

    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    })

    res.status(200).json({ message: 'Password has been reset successfully' })
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Token expired' })
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Invalid token' })
    }
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.params;

  try {
    const user = await prisma.user.findUnique({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    if (user.emailVerificationTokenExpiresAt && user.emailVerificationTokenExpiresAt < new Date()) {
      return res.status(400).json({ message: 'Verification token has expired' });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        emailVerificationToken: null,
        emailVerificationTokenExpiresAt: null,
      },
    });

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};