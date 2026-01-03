import { Router } from 'express';
import { requireRole } from '../middleware/auth';

const router = Router();

// Health check (already handled in main app)
router.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// User routes
router.get('/users/me', (req, res) => {
  res.json({ user: req.user });
});

// Analytics routes (admin only)
router.get('/analytics', requireRole(['admin']), (req, res) => {
  res.json({ message: 'Analytics data' });
});

// Audit logs (admin only)
router.get('/audit-logs', requireRole(['admin']), (req, res) => {
  res.json({ message: 'Audit logs' });
});

export default router;
