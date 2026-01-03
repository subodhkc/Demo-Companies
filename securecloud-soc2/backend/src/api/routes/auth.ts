/**
 * Authentication Routes
 * SOC 2 Control: CC6.1 (Logical Access Security)
 */

import { Router } from 'express';
import { body } from 'express-validator';
import { AuthController } from '../controllers/authController';
import { validateRequest } from '../../middleware/requestValidator';
import { rateLimiter } from '../../middleware/rateLimiter';

const router = Router();
const authController = new AuthController();

// Login - SOC 2 Control: CC6.1
router.post(
  '/login',
  rateLimiter({ windowMs: 15 * 60 * 1000, max: 5 }),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 14 }),
  ],
  validateRequest,
  authController.login
);

// MFA Verification - SOC 2 Control: CC6.1
router.post(
  '/mfa/verify',
  [
    body('token').isLength({ min: 6, max: 6 }),
    body('sessionId').isUUID(),
  ],
  validateRequest,
  authController.verifyMfa
);

// Logout - SOC 2 Control: CC6.1
router.post('/logout', authController.logout);

// Refresh Token
router.post('/refresh', authController.refreshToken);

export default router;
