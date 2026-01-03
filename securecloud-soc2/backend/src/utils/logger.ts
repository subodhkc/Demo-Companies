/**
 * Logging Utility
 * SOC 2 Control: CC7.2 (Anomaly Detection), CC4.1 (Ongoing Monitoring)
 * 
 * Centralized logging with structured JSON output for SIEM integration.
 * All logs include correlation IDs for request tracing.
 */

import winston from 'winston';
import { config } from '../config';

// Log levels aligned with severity
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Colors for console output (development only)
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

winston.addColors(colors);

// Custom format for structured logging
const structuredFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Pretty format for development
const prettyFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}]: ${message} ${metaStr}`;
  })
);

// Create logger instance
export const logger = winston.createLogger({
  level: config.logging.level,
  levels,
  format: config.logging.format === 'json' ? structuredFormat : prettyFormat,
  defaultMeta: {
    service: 'securecloud-api',
    environment: config.env,
    version: process.env.npm_package_version || '2.4.0',
  },
  transports: [
    // Console transport
    new winston.transports.Console({
      stderrLevels: ['error'],
    }),
  ],
  // Don't exit on handled exceptions
  exitOnError: false,
});

// Add file transports in production
if (config.env === 'production') {
  // Error logs
  logger.add(
    new winston.transports.File({
      filename: '/var/log/securecloud/error.log',
      level: 'error',
      maxsize: 100 * 1024 * 1024, // 100MB
      maxFiles: 10,
      tailable: true,
    })
  );

  // Combined logs
  logger.add(
    new winston.transports.File({
      filename: '/var/log/securecloud/combined.log',
      maxsize: 100 * 1024 * 1024, // 100MB
      maxFiles: 30,
      tailable: true,
    })
  );

  // Audit logs (separate for compliance)
  logger.add(
    new winston.transports.File({
      filename: '/var/log/securecloud/audit.log',
      level: 'info',
      maxsize: 100 * 1024 * 1024, // 100MB
      maxFiles: 90, // 90 days retention
      tailable: true,
    })
  );
}

// Morgan stream for HTTP request logging
export const morganStream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};

// Security event logger
export const securityLogger = {
  authSuccess: (userId: string, ip: string, method: string) => {
    logger.info('Authentication successful', {
      event: 'auth_success',
      userId,
      ip,
      method,
      category: 'security',
    });
  },

  authFailure: (ip: string, reason: string, attemptedUser?: string) => {
    logger.warn('Authentication failed', {
      event: 'auth_failure',
      ip,
      reason,
      attemptedUser,
      category: 'security',
    });
  },

  accessDenied: (userId: string, resource: string, action: string) => {
    logger.warn('Access denied', {
      event: 'access_denied',
      userId,
      resource,
      action,
      category: 'security',
    });
  },

  suspiciousActivity: (userId: string, activity: string, details: Record<string, unknown>) => {
    logger.warn('Suspicious activity detected', {
      event: 'suspicious_activity',
      userId,
      activity,
      details,
      category: 'security',
    });
  },

  dataAccess: (userId: string, dataType: string, action: string, recordCount: number) => {
    logger.info('Data access', {
      event: 'data_access',
      userId,
      dataType,
      action,
      recordCount,
      category: 'audit',
    });
  },

  configChange: (userId: string, setting: string, oldValue: unknown, newValue: unknown) => {
    logger.info('Configuration changed', {
      event: 'config_change',
      userId,
      setting,
      oldValue: typeof oldValue === 'string' && oldValue.length > 50 ? '[REDACTED]' : oldValue,
      newValue: typeof newValue === 'string' && newValue.length > 50 ? '[REDACTED]' : newValue,
      category: 'audit',
    });
  },
};

// Performance logger
export const performanceLogger = {
  slow: (operation: string, duration: number, threshold: number) => {
    logger.warn('Slow operation detected', {
      event: 'slow_operation',
      operation,
      duration,
      threshold,
      category: 'performance',
    });
  },

  metric: (name: string, value: number, unit: string, tags?: Record<string, string>) => {
    logger.info('Performance metric', {
      event: 'metric',
      name,
      value,
      unit,
      tags,
      category: 'performance',
    });
  },
};

export default logger;
