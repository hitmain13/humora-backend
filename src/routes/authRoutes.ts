import { Router } from 'express';
import { register, login, forgotPassword, resetPassword, verifyEmail } from '../controllers/authController';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.get('/verify/:token', verifyEmail);

export default router;