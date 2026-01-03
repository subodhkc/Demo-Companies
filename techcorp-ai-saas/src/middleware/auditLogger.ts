import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

interface AuditLogEntry {
  id: string;
  tenantId: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  method: string;
  path: string;
  ipAddress: string;
  userAgent: string;
  requestId: string;
  statusCode?: number;
  duration?: number;
  timestamp: Date;
}

export const auditLogger = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  // Generate unique request ID
  const requestId = uuidv4();
  req.headers['x-request-id'] = requestId;

  // Record start time
  const startTime = Date.now();

  // Skip audit logging for health checks
  if (req.path === '/health') {
    next();
    return;
  }

  // Capture response
  const originalSend = res.send;
  res.send = function (data: any): Response {
    res.send = originalSend;
    
    // Calculate duration
    const duration = Date.now() - startTime;

    // Create audit log entry
    const auditEntry: AuditLogEntry = {
      id: uuidv4(),
      tenantId: req.headers['x-tenant-id'] as string || 'unknown',
      userId: req.user?.id,
      action: `${req.method} ${req.path}`,
      resourceType: extractResourceType(req.path),
      resourceId: extractResourceId(req.path),
      method: req.method,
      path: req.path,
      ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      requestId,
      statusCode: res.statusCode,
      duration,
      timestamp: new Date(),
    };

    // Log based on status code
    if (res.statusCode >= 500) {
      logger.error('Audit log - Server error', auditEntry);
    } else if (res.statusCode >= 400) {
      logger.warn('Audit log - Client error', auditEntry);
    } else {
      logger.info('Audit log', auditEntry);
    }

    // In production, this would also write to database
    // await saveAuditLog(auditEntry);

    return originalSend.call(this, data);
  };

  next();
};

function extractResourceType(path: string): string {
  const segments = path.split('/').filter(Boolean);
  
  // Extract resource type from path
  // e.g., /api/users/123 -> users
  // e.g., /api/analytics/reports -> analytics
  
  if (segments.length >= 2 && segments[0] === 'api') {
    return segments[1];
  }
  
  return 'unknown';
}

function extractResourceId(path: string): string | undefined {
  const segments = path.split('/').filter(Boolean);
  
  // Extract resource ID from path
  // e.g., /api/users/123 -> 123
  // e.g., /api/analytics/reports/abc-def -> abc-def
  
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const numericRegex = /^\d+$/;
  
  for (const segment of segments) {
    if (uuidRegex.test(segment) || numericRegex.test(segment)) {
      return segment;
    }
  }
  
  return undefined;
}

// In production, this would save to database
async function saveAuditLog(entry: AuditLogEntry): Promise<void> {
  // Simulate database insert
  // await db.query(
  //   `INSERT INTO audit_log (id, tenant_id, user_id, action, resource_type, 
  //    resource_id, method, path, ip_address, user_agent, request_id, 
  //    status_code, duration, created_at)
  //    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
  //   [entry.id, entry.tenantId, entry.userId, entry.action, entry.resourceType,
  //    entry.resourceId, entry.method, entry.path, entry.ipAddress, entry.userAgent,
  //    entry.requestId, entry.statusCode, entry.duration, entry.timestamp]
  // );
}
