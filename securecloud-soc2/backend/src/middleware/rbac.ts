/**
 * Role-Based Access Control (RBAC) Middleware
 * SOC 2 Control: CC6.1 (Logical Access Security), CC6.2 (Access Provisioning)
 * 
 * Implements fine-grained permission checking based on user roles.
 * All authorization decisions are logged for audit purposes.
 */

import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { logger } from '../utils/logger';
import { AuditEventType, logAuditEvent } from '../services/auditService';

// Permission definitions
export enum Permission {
  // User permissions
  USER_READ = 'user:read',
  USER_CREATE = 'user:create',
  USER_UPDATE = 'user:update',
  USER_DELETE = 'user:delete',
  
  // Admin permissions
  ADMIN_READ = 'admin:read',
  ADMIN_WRITE = 'admin:write',
  ADMIN_DELETE = 'admin:delete',
  
  // Data permissions
  DATA_READ = 'data:read',
  DATA_WRITE = 'data:write',
  DATA_DELETE = 'data:delete',
  DATA_EXPORT = 'data:export',
  
  // Security permissions
  SECURITY_READ = 'security:read',
  SECURITY_WRITE = 'security:write',
  SECURITY_AUDIT = 'security:audit',
  
  // System permissions
  SYSTEM_CONFIG = 'system:config',
  SYSTEM_LOGS = 'system:logs',
  SYSTEM_METRICS = 'system:metrics',
}

// Role definitions with associated permissions
export const RolePermissions: Record<string, Permission[]> = {
  super_admin: Object.values(Permission),
  
  admin: [
    Permission.USER_READ,
    Permission.USER_CREATE,
    Permission.USER_UPDATE,
    Permission.ADMIN_READ,
    Permission.DATA_READ,
    Permission.DATA_WRITE,
    Permission.SECURITY_READ,
    Permission.SYSTEM_LOGS,
    Permission.SYSTEM_METRICS,
  ],
  
  security_admin: [
    Permission.USER_READ,
    Permission.SECURITY_READ,
    Permission.SECURITY_WRITE,
    Permission.SECURITY_AUDIT,
    Permission.SYSTEM_LOGS,
  ],
  
  developer: [
    Permission.USER_READ,
    Permission.DATA_READ,
    Permission.DATA_WRITE,
    Permission.SYSTEM_LOGS,
    Permission.SYSTEM_METRICS,
  ],
  
  analyst: [
    Permission.USER_READ,
    Permission.DATA_READ,
    Permission.DATA_EXPORT,
    Permission.SYSTEM_METRICS,
  ],
  
  support: [
    Permission.USER_READ,
    Permission.DATA_READ,
  ],
  
  viewer: [
    Permission.USER_READ,
    Permission.DATA_READ,
  ],
};

/**
 * Get all permissions for a set of roles
 */
export const getPermissionsForRoles = (roles: string[]): Permission[] => {
  const permissions = new Set<Permission>();
  
  for (const role of roles) {
    const rolePerms = RolePermissions[role] || [];
    rolePerms.forEach(perm => permissions.add(perm));
  }
  
  return Array.from(permissions);
};

/**
 * Check if user has a specific permission
 */
export const hasPermission = (
  userPermissions: string[],
  requiredPermission: Permission
): boolean => {
  return userPermissions.includes(requiredPermission);
};

/**
 * Check if user has any of the specified permissions
 */
export const hasAnyPermission = (
  userPermissions: string[],
  requiredPermissions: Permission[]
): boolean => {
  return requiredPermissions.some(perm => userPermissions.includes(perm));
};

/**
 * Check if user has all of the specified permissions
 */
export const hasAllPermissions = (
  userPermissions: string[],
  requiredPermissions: Permission[]
): boolean => {
  return requiredPermissions.every(perm => userPermissions.includes(perm));
};

/**
 * RBAC middleware - validates user has required permissions
 */
export const rbacMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  // Skip RBAC for public routes
  if (!req.user) {
    next();
    return;
  }

  // Get user permissions from roles
  const userPermissions = getPermissionsForRoles(req.user.roles);
  
  // Attach permissions to request for use in controllers
  req.user.permissions = userPermissions;

  next();
};

/**
 * Factory function to create permission-checking middleware
 */
export const requirePermission = (permission: Permission) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const requestId = req.headers['x-request-id'] as string || 'unknown';

    if (!req.user) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
      return;
    }

    const userPermissions = req.user.permissions || getPermissionsForRoles(req.user.roles);

    if (!hasPermission(userPermissions, permission)) {
      await logAuditEvent({
        type: AuditEventType.AUTHZ_FAILURE,
        action: 'permission_denied',
        userId: req.user.id,
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
        metadata: {
          requiredPermission: permission,
          userRoles: req.user.roles,
        },
      });

      logger.warn('Permission denied', {
        userId: req.user.id,
        requiredPermission: permission,
        userRoles: req.user.roles,
        path: req.path,
        method: req.method,
      });

      res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have permission to perform this action',
        code: 'PERMISSION_DENIED',
      });
      return;
    }

    await logAuditEvent({
      type: AuditEventType.AUTHZ_SUCCESS,
      action: 'permission_granted',
      userId: req.user.id,
      requestId,
      ip: req.ip || 'unknown',
      path: req.path,
      method: req.method,
      metadata: {
        permission,
      },
    });

    next();
  };
};

/**
 * Factory function to require any of multiple permissions
 */
export const requireAnyPermission = (permissions: Permission[]) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const requestId = req.headers['x-request-id'] as string || 'unknown';

    if (!req.user) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
      return;
    }

    const userPermissions = req.user.permissions || getPermissionsForRoles(req.user.roles);

    if (!hasAnyPermission(userPermissions, permissions)) {
      await logAuditEvent({
        type: AuditEventType.AUTHZ_FAILURE,
        action: 'permission_denied',
        userId: req.user.id,
        requestId,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        path: req.path,
        method: req.method,
        metadata: {
          requiredPermissions: permissions,
          userRoles: req.user.roles,
        },
      });

      res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have permission to perform this action',
        code: 'PERMISSION_DENIED',
      });
      return;
    }

    next();
  };
};

/**
 * Factory function to require a specific role
 */
export const requireRole = (role: string) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
      return;
    }

    if (!req.user.roles.includes(role)) {
      res.status(403).json({
        error: 'Forbidden',
        message: 'Insufficient role privileges',
        code: 'ROLE_REQUIRED',
      });
      return;
    }

    next();
  };
};
