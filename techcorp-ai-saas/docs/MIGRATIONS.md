# Database Migrations

## Migration History

### Migration 2025-12-15-001: Add MFA Tables
**Status**: Completed
**Applied**: December 15, 2025
**Rollback**: Available

```sql
-- Add MFA configuration table
CREATE TABLE user_mfa_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_type VARCHAR(20) NOT NULL CHECK (mfa_type IN ('totp', 'sms', 'email')),
    secret_encrypted TEXT NOT NULL,
    backup_codes_encrypted TEXT[],
    is_enabled BOOLEAN DEFAULT false,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, mfa_type)
);

-- Add MFA audit log
CREATE TABLE mfa_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add indexes
CREATE INDEX idx_mfa_config_user_id ON user_mfa_config(user_id);
CREATE INDEX idx_mfa_audit_user_id ON mfa_audit_log(user_id);
CREATE INDEX idx_mfa_audit_created_at ON mfa_audit_log(created_at);

-- Add encryption key rotation tracking
ALTER TABLE user_mfa_config ADD COLUMN key_version INTEGER DEFAULT 1;
```

**Impact**: All users required to enable MFA within 30 days
**Security**: Secrets encrypted using AES-256-GCM with tenant-specific keys

---

### Migration 2025-11-20-001: Enhanced Audit Logging
**Status**: Completed
**Applied**: November 20, 2025
**Rollback**: Available

```sql
-- Create comprehensive audit log table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id UUID,
    session_id UUID,
    severity VARCHAR(20) CHECK (severity IN ('info', 'warning', 'critical')),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Partition by month for performance
CREATE TABLE audit_log_2025_12 PARTITION OF audit_log
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Add indexes
CREATE INDEX idx_audit_tenant_created ON audit_log(tenant_id, created_at DESC);
CREATE INDEX idx_audit_user_created ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_severity ON audit_log(severity, created_at DESC);

-- Enable row-level security
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (tenant_id = current_setting('app.current_tenant')::UUID);
```

**Retention**: 1 year for all audit logs, 7 years for financial transactions
**Compliance**: Meets SOC 2 and ISO 27001 requirements

---

### Migration 2025-10-10-001: Data Classification
**Status**: Completed
**Applied**: October 10, 2025
**Rollback**: Not available (one-way migration)

```sql
-- Add data classification to all tables with sensitive data
ALTER TABLE users ADD COLUMN data_classification VARCHAR(20) DEFAULT 'confidential';
ALTER TABLE customer_data ADD COLUMN data_classification VARCHAR(20) DEFAULT 'critical';
ALTER TABLE analytics_data ADD COLUMN data_classification VARCHAR(20) DEFAULT 'internal';

-- Add data retention policies
CREATE TABLE data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    retention_days INTEGER NOT NULL,
    classification VARCHAR(20) NOT NULL,
    deletion_method VARCHAR(50) DEFAULT 'soft_delete',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Insert default policies
INSERT INTO data_retention_policies (table_name, retention_days, classification) VALUES
    ('audit_log', 365, 'confidential'),
    ('customer_data', 2555, 'critical'),  -- 7 years
    ('analytics_data', 90, 'internal'),
    ('system_logs', 90, 'internal');

-- Add automated deletion job tracking
CREATE TABLE data_deletion_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    records_deleted INTEGER,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(20) CHECK (status IN ('pending', 'running', 'completed', 'failed'))
);
```

**Impact**: Automated data retention enforcement
**Compliance**: GDPR data minimization requirement

---

### Migration 2025-09-01-001: Tenant Isolation Enhancement
**Status**: Completed
**Applied**: September 1, 2025
**Rollback**: Available

```sql
-- Add tenant_id to all tables for multi-tenancy
ALTER TABLE api_keys ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);
ALTER TABLE sessions ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);
ALTER TABLE webhooks ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);

-- Enable row-level security on all tenant tables
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;

-- Create tenant isolation policies
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY sessions_tenant_isolation ON sessions
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY webhooks_tenant_isolation ON webhooks
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- Add tenant-specific encryption keys
CREATE TABLE tenant_encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    key_type VARCHAR(50) NOT NULL,
    key_encrypted TEXT NOT NULL,
    key_version INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    rotated_at TIMESTAMP
);
```

**Security**: Complete tenant data isolation at database level
**Performance**: Minimal impact, < 5ms query overhead

---

### Migration 2025-07-15-001: GDPR Compliance Tables
**Status**: Completed
**Applied**: July 15, 2025
**Rollback**: Not available

```sql
-- Data subject access requests (DSAR)
CREATE TABLE data_subject_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('access', 'deletion', 'portability', 'rectification')),
    status VARCHAR(20) CHECK (status IN ('pending', 'processing', 'completed', 'rejected')),
    requested_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    data_package_url TEXT,
    notes TEXT
);

-- Consent management
CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    consent_type VARCHAR(50) NOT NULL,
    purpose TEXT NOT NULL,
    granted BOOLEAN DEFAULT false,
    granted_at TIMESTAMP,
    withdrawn_at TIMESTAMP,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Data processing activities (Article 30)
CREATE TABLE processing_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    activity_name VARCHAR(200) NOT NULL,
    purpose TEXT NOT NULL,
    legal_basis VARCHAR(50) NOT NULL,
    data_categories TEXT[],
    data_subjects TEXT[],
    recipients TEXT[],
    retention_period VARCHAR(100),
    security_measures TEXT[],
    dpo_reviewed BOOLEAN DEFAULT false,
    last_reviewed TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Compliance**: GDPR Articles 15, 17, 20, 30
**SLA**: DSAR completion within 30 days

---

### Migration 2025-05-20-001: Access Control Enhancement
**Status**: Completed
**Applied**: May 20, 2025
**Rollback**: Available

```sql
-- Role-based access control (RBAC)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL,
    is_system_role BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- User role assignments
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    role_id UUID NOT NULL REFERENCES roles(id),
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    UNIQUE(user_id, role_id)
);

-- Permission audit log
CREATE TABLE permission_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    role_id UUID REFERENCES roles(id),
    action VARCHAR(50) NOT NULL,
    old_permissions JSONB,
    new_permissions JSONB,
    changed_by UUID REFERENCES users(id),
    reason TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert default roles
INSERT INTO roles (tenant_id, name, permissions, is_system_role) VALUES
    ('00000000-0000-0000-0000-000000000000', 'admin', '{"all": true}', true),
    ('00000000-0000-0000-0000-000000000000', 'user', '{"read": true, "write": false}', true),
    ('00000000-0000-0000-0000-000000000000', 'viewer', '{"read": true}', true);
```

**Security**: Least privilege access model
**Compliance**: SOC 2 CC6.1, CC6.2

---

### Migration 2025-03-10-001: Session Management
**Status**: Completed
**Applied**: March 10, 2025
**Rollback**: Available

```sql
-- Enhanced session tracking
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    session_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) UNIQUE,
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    last_activity TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Session security events
CREATE TABLE session_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id),
    event_type VARCHAR(50) NOT NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add indexes
CREATE INDEX idx_sessions_user_active ON sessions(user_id, is_active);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- Automatic session cleanup
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;
```

**Security**: 30-minute idle timeout, 24-hour absolute timeout
**Performance**: Automatic cleanup of expired sessions

---

### Migration 2025-01-15-001: Encryption at Rest
**Status**: Completed
**Applied**: January 15, 2025
**Rollback**: Not available (data encrypted)

```sql
-- Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encrypt sensitive columns
ALTER TABLE users ADD COLUMN email_encrypted BYTEA;
UPDATE users SET email_encrypted = pgp_sym_encrypt(email, current_setting('app.encryption_key'));
ALTER TABLE users DROP COLUMN email;
ALTER TABLE users RENAME COLUMN email_encrypted TO email;

ALTER TABLE api_keys ADD COLUMN key_encrypted BYTEA;
UPDATE api_keys SET key_encrypted = pgp_sym_encrypt(key_value, current_setting('app.encryption_key'));
ALTER TABLE api_keys DROP COLUMN key_value;
ALTER TABLE api_keys RENAME COLUMN key_encrypted TO key_value;

-- Create encryption key rotation tracking
CREATE TABLE encryption_key_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_version INTEGER NOT NULL,
    rotated_at TIMESTAMP DEFAULT NOW(),
    rotated_by UUID REFERENCES users(id),
    tables_affected TEXT[],
    status VARCHAR(20) CHECK (status IN ('pending', 'in_progress', 'completed', 'failed'))
);
```

**Security**: AES-256 encryption for all PII
**Compliance**: SOC 2 CC6.7, GDPR Article 32

---

## Migration Best Practices

### Pre-Migration Checklist
- [ ] Backup database
- [ ] Test migration in staging environment
- [ ] Review rollback procedure
- [ ] Notify stakeholders
- [ ] Schedule maintenance window
- [ ] Prepare monitoring alerts

### Post-Migration Checklist
- [ ] Verify data integrity
- [ ] Run performance tests
- [ ] Check application functionality
- [ ] Monitor error logs
- [ ] Update documentation
- [ ] Notify stakeholders of completion

### Rollback Procedure
1. Stop application servers
2. Restore database from backup
3. Apply rollback migration script
4. Verify data integrity
5. Restart application servers
6. Monitor for issues

## Migration Schedule

### Upcoming Migrations (Q1 2026)
- **2026-01-15**: Add AI model versioning tables
- **2026-02-01**: Implement data residency controls
- **2026-03-01**: Enhanced threat intelligence integration

### Maintenance Windows
- **Regular**: Every 2nd Saturday, 2:00 AM - 4:00 AM UTC
- **Emergency**: As needed with 2-hour notice
- **Major**: Quarterly, scheduled 2 weeks in advance

## Contact
For migration questions or issues:
- **Database Team**: database@techcorp-ai.com
- **On-call DBA**: +1-555-DBA-HELP

**Last Updated**: December 15, 2025
