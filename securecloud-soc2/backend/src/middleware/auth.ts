/**
 * Authentication Middleware
 * SOC 2 Control: CC6.1 (Logical Access Security)
 * 
 * Implements JWT-based authentication with MFA verification.
 * All authentication events are logged for audit purposes.
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { logger } from '../utils/logger';
import { redis } from '../services/redis';
import { AuditEventType, logAuditEvent } from '../services/auditService';

// Extended request interface with user context
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    roles: string[];
    permissions: string[];
    mfaVerified: boolean;
    sessionId: string;
    tenantId: string;
  };
}

// JWT payload structure
interface JWTPayload {
  sub: string;
  email: string;
  roles: string[];
  permissions: string[];
  mfaVerified: boolean;
  sessionId: string;
  tenantId: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

/**
 * Authentication middleware
 * Validates JWT tokens and enforces MFA requirements
 */
export const authMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const requestId = req.headers['x-request-id'] as string || 'unknown';
  const startTime = Date.now();

  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      await logAuditEvent({
        type: AuditEventType.AUTH_FAILURE,
        action: 'token_missing',
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication token is required',
        code: 'AUTH_TOKEN_MISSING',
      });
      return;
    }

    const token = authHeader.substring(7);

    // Check if token is blacklisted (logged out)
    const isBlacklisted = await redis.get(`blacklist:${token}`);
    if (isBlacklisted) {
      await logAuditEvent({
        type: AuditEventType.AUTH_FAILURE,
        action: 'token_blacklisted',
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Token has been revoked',
        code: 'AUTH_TOKEN_REVOKED',
      });
      return;
    }

    // Verify JWT token
    const decoded = jwt.verify(token, config.jwt.secret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      algorithms: ['HS256'],
    }) as JWTPayload;

    // Validate session is still active
    const sessionKey = `session:${decoded.sessionId}`;
    const sessionData = await redis.get(sessionKey);
    
    if (!sessionData) {
      await logAuditEvent({
        type: AuditEventType.AUTH_FAILURE,
        action: 'session_expired',
        userId: decoded.sub,
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Session has expired',
        code: 'AUTH_SESSION_EXPIRED',
      });
      return;
    }

    // Check MFA requirement for sensitive operations
    const mfaRequiredPaths = [
      '/api/v1/admin',
      '/api/v1/users',
      '/api/v1/settings',
      '/api/v1/security',
    ];

    const requiresMfa = mfaRequiredPaths.some(path => req.path.startsWith(path));
    
    if (requiresMfa && !decoded.mfaVerified) {
      await logAuditEvent({
        type: AuditEventType.AUTH_FAILURE,
        action: 'mfa_required',
        userId: decoded.sub,
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
      });

      res.status(403).json({
        error: 'Forbidden',
        message: 'MFA verification required for this operation',
        code: 'AUTH_MFA_REQUIRED',
      });
      return;
    }

    // Attach user context to request
    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.roles,
      permissions: decoded.permissions,
      mfaVerified: decoded.mfaVerified,
      sessionId: decoded.sessionId,
      tenantId: decoded.tenantId,
    };

    // Refresh session TTL
    await redis.expire(sessionKey, config.session.timeout);

    // Log successful authentication
    logger.debug('Authentication successful', {
      userId: decoded.sub,
      sessionId: decoded.sessionId,
      path: req.path,
      method: req.method,
      duration: Date.now() - startTime,
    });

    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      await logAuditEvent({
        type: AuditEventType.AUTH_FAILURE,
        action: 'token_expired',
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Token has expired',
        code: 'AUTH_TOKEN_EXPIRED',
      });
      return;
    }

    if (error instanceof jwt.JsonWebTokenError) {
      await logAuditEvent({
        type: AuditEventType.AUTH_FAILURE,
        action: 'token_invalid',
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
        metadata: { error: error.message },
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid token',
        code: 'AUTH_TOKEN_INVALID',
      });
      return;
    }

    logger.error('Authentication error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      requestId,
      path: req.path,
    });

    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Authentication failed',
      code: 'AUTH_ERROR',
    });
  }
};

/**
 * Optional authentication middleware
 * Attaches user context if token is present, but doesn't require it
 */
export const optionalAuthMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    next();
    return;
  }

  // Delegate to main auth middleware
  await authMiddleware(req, res, next);
};

/**
 * MFA verification middleware
 * Requires MFA to be verified for the current session
 */
export const requireMfaMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  if (!req.user?.mfaVerified) {
    res.status(403).json({
      error: 'Forbidden',
      message: 'MFA verification required',
      code: 'MFA_REQUIRED',
    });
    return;
  }

  next();
};
