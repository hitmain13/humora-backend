import { Router } from 'express'

import {
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyEmail,
  logout,
} from '../controllers/authController'
import { validate } from '../middlewares/validateRequest'
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '../schemas/authSchemas'

const router = Router()

router.post('/register', validate(registerSchema), register)
router.post('/login', validate(loginSchema), login)
router.post('/forgot-password', validate(forgotPasswordSchema), forgotPassword)
router.post('/reset-password', validate(resetPasswordSchema), resetPassword)
router.get('/verify/:token', verifyEmail)
router.post('/logout', logout)

export default router
