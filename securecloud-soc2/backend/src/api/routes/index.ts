/**
 * API Routes
 * SOC 2 Control: CC5.2 (Technology Controls)
 */

import { Router } from 'express';
import authRoutes from './auth';
import userRoutes from './users';
import dataRoutes from './data';
import adminRoutes from './admin';
import auditRoutes from './audit';

const router = Router();

// Mount routes
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/data', dataRoutes);
router.use('/admin', adminRoutes);
router.use('/audit', auditRoutes);

export default router;
