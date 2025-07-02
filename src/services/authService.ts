import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../config/prisma';

export const registerUser = async (email: string, password: string) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET!, { expiresIn: '1h' });

  const user = await prisma.user.create({
    data: {
      email,
      password: hashedPassword,
      emailVerificationToken: verificationToken,
      emailVerificationTokenExpiresAt: new Date(Date.now() + 3600000),
    },
  });

  console.log(`Verification token for ${email}: ${verificationToken}`);
  return user;
};

export const loginUser = async (email: string, password: string) => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    throw new Error('Invalid credentials');
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    throw new Error('Invalid credentials');
  }

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '1h' });
  return token;
};

export const sendPasswordResetLink = async (email: string) => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    throw new Error('User not found');
  }

  const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '15m' });

  console.log(`Password reset token for ${email}: ${resetToken}`);
  return resetToken;
};

export const resetUserPassword = async (token: string, newPassword: string) => {
  const decoded: any = jwt.verify(token, process.env.JWT_SECRET!); 

  const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

  if (!user) {
    throw new Error('Invalid or expired token');
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashedPassword },
  });
};

export const verifyUserEmail = async (token: string) => {
  const user = await prisma.user.findUnique({
    where: { emailVerificationToken: token },
  });

  if (!user) {
    throw new Error('Invalid or expired verification token');
  }

  if (user.emailVerificationTokenExpiresAt && user.emailVerificationTokenExpiresAt < new Date()) {
    throw new Error('Verification token has expired');
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      isVerified: true,
      emailVerificationToken: null,
      emailVerificationTokenExpiresAt: null,
    },
  });
};