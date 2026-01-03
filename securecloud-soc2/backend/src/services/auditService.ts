/**
 * Audit Service
 * SOC 2 Control: CC7.2 (Anomaly Detection), CC4.1 (Ongoing Monitoring)
 */

import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

export enum AuditEventType {
  AUTH_SUCCESS = 'auth_success',
  AUTH_FAILURE = 'auth_failure',
  AUTHZ_SUCCESS = 'authz_success',
  AUTHZ_FAILURE = 'authz_failure',
  DATA_ACCESS = 'data_access',
  DATA_MODIFY = 'data_modify',
  CONFIG_CHANGE = 'config_change',
  SECURITY_EVENT = 'security_event',
}

interface AuditEvent {
  type: AuditEventType;
  action: string;
  userId?: string;
  requestId?: string;
  ip?: string;
  userAgent?: string;
  path?: string;
  method?: string;
  metadata?: Record<string, unknown>;
}

export const logAuditEvent = async (event: AuditEvent): Promise<void> => {
  const auditEntry = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    ...event,
  };

  logger.info('Audit event', auditEntry);
  
  // In production, send to immutable audit log storage
};
