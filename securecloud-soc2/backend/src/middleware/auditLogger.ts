/**
 * Audit Logging Middleware
 * SOC 2 Control: CC7.2 (Anomaly Detection), CC4.1 (Ongoing Monitoring)
 * 
 * Captures all API requests and responses for audit trail.
 * Logs are immutable and sent to centralized logging system.
 */

import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { AuthenticatedRequest } from './auth';

// Audit log entry structure
interface AuditLogEntry {
  id: string;
  timestamp: string;
  requestId: string;
  correlationId: string;
  userId: string | null;
  tenantId: string | null;
  sessionId: string | null;
  ip: string;
  userAgent: string;
  method: string;
  path: string;
  query: Record<string, unknown>;
  statusCode: number;
  responseTime: number;
  requestSize: number;
  responseSize: number;
  error: string | null;
  metadata: Record<string, unknown>;
}

// Sensitive fields to redact from logs
const SENSITIVE_FIELDS = [
  'password',
  'token',
  'secret',
  'apiKey',
  'authorization',
  'cookie',
  'creditCard',
  'ssn',
  'socialSecurityNumber',
];

/**
 * Redact sensitive data from objects
 */
const redactSensitiveData = (obj: Record<string, unknown>): Record<string, unknown> => {
  const redacted: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    
    if (SENSITIVE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactSensitiveData(value as Record<string, unknown>);
    } else {
      redacted[key] = value;
    }
  }
  
  return redacted;
};

/**
 * Calculate request body size
 */
const getRequestSize = (req: Request): number => {
  const contentLength = req.headers['content-length'];
  return contentLength ? parseInt(contentLength, 10) : 0;
};

/**
 * Audit logging middleware
 */
export const auditLogger = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  const startTime = Date.now();
  
  // Generate or extract request ID
  const requestId = (req.headers['x-request-id'] as string) || uuidv4();
  const correlationId = (req.headers['x-correlation-id'] as string) || requestId;
  
  // Attach request ID to response headers
  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Correlation-ID', correlationId);
  
  // Capture original response methods
  const originalSend = res.send;
  const originalJson = res.json;
  let responseBody: unknown;
  let responseSize = 0;

  // Override send to capture response
  res.send = function (body: unknown): Response {
    responseBody = body;
    responseSize = typeof body === 'string' ? Buffer.byteLength(body) : 0;
    return originalSend.call(this, body);
  };

  // Override json to capture response
  res.json = function (body: unknown): Response {
    responseBody = body;
    responseSize = JSON.stringify(body).length;
    return originalJson.call(this, body);
  };

  // Log on response finish
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    
    const auditEntry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      requestId,
      correlationId,
      userId: req.user?.id || null,
      tenantId: req.user?.tenantId || null,
      sessionId: req.user?.sessionId || null,
      ip: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      method: req.method,
      path: req.path,
      query: redactSensitiveData(req.query as Record<string, unknown>),
      statusCode: res.statusCode,
      responseTime,
      requestSize: getRequestSize(req),
      responseSize,
      error: res.statusCode >= 400 ? extractErrorMessage(responseBody) : null,
      metadata: {
        protocol: req.protocol,
        hostname: req.hostname,
        originalUrl: req.originalUrl,
        contentType: req.get('Content-Type'),
        acceptLanguage: req.get('Accept-Language'),
      },
    };

    // Log based on status code
    if (res.statusCode >= 500) {
      logger.error('API Request - Server Error', auditEntry);
    } else if (res.statusCode >= 400) {
      logger.warn('API Request - Client Error', auditEntry);
    } else {
      logger.info('API Request', auditEntry);
    }

    // Send to audit log service for immutable storage
    sendToAuditService(auditEntry).catch(err => {
      logger.error('Failed to send audit log', { error: err.message, requestId });
    });
  });

  next();
};

/**
 * Extract error message from response body
 */
const extractErrorMessage = (body: unknown): string | null => {
  if (!body) return null;
  
  if (typeof body === 'string') {
    try {
      const parsed = JSON.parse(body);
      return parsed.message || parsed.error || null;
    } catch {
      return body.substring(0, 200);
    }
  }
  
  if (typeof body === 'object') {
    const obj = body as Record<string, unknown>;
    return (obj.message || obj.error || null) as string | null;
  }
  
  return null;
};

/**
 * Send audit log to centralized audit service
 * SOC 2 Control: CC7.2 - Immutable audit trail
 */
const sendToAuditService = async (entry: AuditLogEntry): Promise<void> => {
  // In production, this would send to:
  // - Splunk
  // - AWS CloudWatch
  // - Elasticsearch
  // - S3 for long-term storage
  
  // For demo purposes, we'll just log that it was sent
  logger.debug('Audit log sent to centralized service', {
    id: entry.id,
    requestId: entry.requestId,
  });
};

/**
 * Create a child logger with request context
 */
export const createRequestLogger = (req: AuthenticatedRequest) => {
  const requestId = req.headers['x-request-id'] as string;
  const correlationId = req.headers['x-correlation-id'] as string;
  
  return {
    info: (message: string, meta?: Record<string, unknown>) => {
      logger.info(message, { ...meta, requestId, correlationId, userId: req.user?.id });
    },
    warn: (message: string, meta?: Record<string, unknown>) => {
      logger.warn(message, { ...meta, requestId, correlationId, userId: req.user?.id });
    },
    error: (message: string, meta?: Record<string, unknown>) => {
      logger.error(message, { ...meta, requestId, correlationId, userId: req.user?.id });
    },
    debug: (message: string, meta?: Record<string, unknown>) => {
      logger.debug(message, { ...meta, requestId, correlationId, userId: req.user?.id });
    },
  };
};
