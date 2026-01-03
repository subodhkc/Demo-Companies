import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import { logger } from '../utils/logger';

export const tenantIsolation = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  // Skip tenant isolation for health checks and public endpoints
  if (req.path === '/health' || req.path.startsWith('/public/')) {
    next();
    return;
  }

  // Extract tenant ID from header or authenticated user
  const tenantIdFromHeader = req.headers['x-tenant-id'] as string;
  const tenantIdFromUser = req.user?.tenantId;

  // Determine the tenant ID to use
  const tenantId = tenantIdFromUser || tenantIdFromHeader;

  if (!tenantId) {
    logger.warn('Missing tenant ID', {
      path: req.path,
      ip: req.ip,
      userId: req.user?.id,
    });

    res.status(400).json({
      error: 'Bad Request',
      message: 'Tenant ID is required',
    });
    return;
  }

  // Validate tenant ID format (UUID)
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(tenantId)) {
    logger.warn('Invalid tenant ID format', {
      tenantId,
      path: req.path,
      userId: req.user?.id,
    });

    res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid tenant ID format',
    });
    return;
  }

  // If user is authenticated, verify tenant ID matches
  if (req.user && req.user.tenantId !== tenantId) {
    logger.warn('Tenant ID mismatch', {
      userTenantId: req.user.tenantId,
      requestedTenantId: tenantId,
      userId: req.user.id,
      path: req.path,
    });

    res.status(403).json({
      error: 'Forbidden',
      message: 'Access denied to this tenant',
    });
    return;
  }

  // Set tenant ID in request context for database queries
  req.headers['x-tenant-id'] = tenantId;

  // Log tenant access
  logger.debug('Tenant access', {
    tenantId,
    userId: req.user?.id,
    path: req.path,
    method: req.method,
  });

  next();
};

export const validateTenantAccess = async (
  userId: string,
  tenantId: string
): Promise<boolean> => {
  // In production, this would query the database
  // For demo purposes, we'll simulate the check
  
  try {
    // Simulate database query to verify user has access to tenant
    // const hasAccess = await db.query(
    //   'SELECT 1 FROM user_tenants WHERE user_id = $1 AND tenant_id = $2',
    //   [userId, tenantId]
    // );
    
    // For demo, always return true
    return true;
  } catch (error) {
    logger.error('Error validating tenant access', { error, userId, tenantId });
    return false;
  }
};
