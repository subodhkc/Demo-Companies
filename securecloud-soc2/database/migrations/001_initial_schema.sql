-- Migration: 001_initial_schema
-- Author: David Kim
-- Date: 2024-01-15
-- Ticket: INFRA-2024-001
-- SOC 2 Control: CC8.1 (Change Management)
-- Rollback: Yes

-- =============================================================================
-- USERS TABLE - SOC 2 Control: CC6.1 (Logical Access Security)
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(255) NOT NULL,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Profile
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(20),
    avatar_url TEXT,
    
    -- MFA - SOC 2 Control: CC6.1
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret_encrypted TEXT,
    mfa_backup_codes_encrypted TEXT,
    mfa_verified_at TIMESTAMP WITH TIME ZONE,
    
    -- Account status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'locked')),
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    
    -- Tenant isolation - SOC 2 Control: CC6.6
    tenant_id UUID NOT NULL,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID,
    updated_by UUID,
    
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_status ON users(status);

-- =============================================================================
-- ROLES TABLE - SOC 2 Control: CC6.2 (Access Provisioning)
-- =============================================================================

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    tenant_id UUID,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default roles
INSERT INTO roles (name, display_name, description, is_system) VALUES
    ('super_admin', 'Super Administrator', 'Full system access', TRUE),
    ('admin', 'Administrator', 'Tenant administration', TRUE),
    ('security_admin', 'Security Administrator', 'Security and audit access', TRUE),
    ('developer', 'Developer', 'Development access', TRUE),
    ('analyst', 'Analyst', 'Read and export access', TRUE),
    ('support', 'Support', 'Customer support access', TRUE),
    ('viewer', 'Viewer', 'Read-only access', TRUE);

-- =============================================================================
-- PERMISSIONS TABLE - SOC 2 Control: CC6.1
-- =============================================================================

CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert permissions
INSERT INTO permissions (name, display_name, category) VALUES
    ('user:read', 'View Users', 'users'),
    ('user:create', 'Create Users', 'users'),
    ('user:update', 'Update Users', 'users'),
    ('user:delete', 'Delete Users', 'users'),
    ('admin:read', 'View Admin Settings', 'admin'),
    ('admin:write', 'Modify Admin Settings', 'admin'),
    ('data:read', 'View Data', 'data'),
    ('data:write', 'Modify Data', 'data'),
    ('data:delete', 'Delete Data', 'data'),
    ('data:export', 'Export Data', 'data'),
    ('security:read', 'View Security Settings', 'security'),
    ('security:write', 'Modify Security Settings', 'security'),
    ('security:audit', 'Access Audit Logs', 'security'),
    ('system:config', 'System Configuration', 'system'),
    ('system:logs', 'View System Logs', 'system'),
    ('system:metrics', 'View Metrics', 'system');

-- =============================================================================
-- ROLE_PERMISSIONS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- =============================================================================
-- USER_ROLES TABLE - SOC 2 Control: CC6.2
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- =============================================================================
-- SESSIONS TABLE - SOC 2 Control: CC6.1
-- =============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255),
    
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    
    mfa_verified BOOLEAN DEFAULT FALSE,
    mfa_verified_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(100)
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_token ON sessions(token_hash);

-- =============================================================================
-- AUDIT_LOGS TABLE - SOC 2 Control: CC7.2 (Anomaly Detection)
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Event details
    event_type VARCHAR(50) NOT NULL,
    event_action VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'info' CHECK (severity IN ('debug', 'info', 'warn', 'error', 'critical')),
    
    -- Actor
    user_id UUID,
    user_email VARCHAR(255),
    tenant_id UUID,
    session_id UUID,
    
    -- Request context
    request_id UUID,
    correlation_id UUID,
    ip_address INET,
    user_agent TEXT,
    
    -- Resource
    resource_type VARCHAR(100),
    resource_id UUID,
    
    -- Change details
    old_values JSONB,
    new_values JSONB,
    
    -- Additional metadata
    metadata JSONB,
    
    -- Immutability - logs cannot be updated or deleted
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Partition by month for performance
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- =============================================================================
-- TENANTS TABLE - SOC 2 Control: CC6.6 (System Boundaries)
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    
    -- Settings
    settings JSONB DEFAULT '{}',
    features JSONB DEFAULT '{}',
    
    -- Subscription
    plan VARCHAR(50) DEFAULT 'free',
    subscription_status VARCHAR(20) DEFAULT 'active',
    
    -- Security settings
    mfa_required BOOLEAN DEFAULT FALSE,
    password_policy JSONB DEFAULT '{"minLength": 14, "requireUppercase": true, "requireNumbers": true, "requireSpecial": true}',
    session_timeout INTEGER DEFAULT 900,
    
    -- Data classification
    data_classification VARCHAR(20) DEFAULT 'confidential',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);

-- =============================================================================
-- API_KEYS TABLE - SOC 2 Control: CC6.1
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    
    scopes TEXT[] DEFAULT '{}',
    rate_limit INTEGER DEFAULT 1000,
    
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- =============================================================================
-- TRIGGERS FOR AUDIT TRAIL
-- =============================================================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Audit log trigger for users table
CREATE OR REPLACE FUNCTION audit_users_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (event_type, event_action, event_category, user_id, resource_type, resource_id, new_values)
        VALUES ('user', 'created', 'access_control', NEW.created_by, 'user', NEW.id, to_jsonb(NEW));
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (event_type, event_action, event_category, user_id, resource_type, resource_id, old_values, new_values)
        VALUES ('user', 'updated', 'access_control', NEW.updated_by, 'user', NEW.id, to_jsonb(OLD), to_jsonb(NEW));
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (event_type, event_action, event_category, resource_type, resource_id, old_values)
        VALUES ('user', 'deleted', 'access_control', 'user', OLD.id, to_jsonb(OLD));
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_audit
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION audit_users_changes();

-- =============================================================================
-- ROW LEVEL SECURITY - SOC 2 Control: CC6.6 (Tenant Isolation)
-- =============================================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Users can only see users in their tenant
CREATE POLICY users_tenant_isolation ON users
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- API keys can only be accessed by their tenant
CREATE POLICY api_keys_tenant_isolation ON api_keys
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- =============================================================================
-- GRANTS - SOC 2 Control: CC6.2 (Access Provisioning)
-- =============================================================================

-- Application roles
GRANT SELECT ON users TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON users TO app_readwrite;
GRANT ALL ON users TO app_admin;

GRANT SELECT ON roles TO app_readonly;
GRANT SELECT ON permissions TO app_readonly;
GRANT SELECT ON role_permissions TO app_readonly;

GRANT SELECT ON audit_logs TO app_readonly;
GRANT INSERT ON audit_logs TO app_readwrite;
-- No UPDATE or DELETE on audit_logs - immutable

GRANT SELECT ON tenants TO app_readonly;
GRANT SELECT, UPDATE ON tenants TO app_readwrite;
GRANT ALL ON tenants TO app_admin;

GRANT SELECT ON sessions TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON sessions TO app_readwrite;

GRANT SELECT ON api_keys TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON api_keys TO app_readwrite;
GRANT ALL ON api_keys TO app_admin;

-- =============================================================================
-- COMMENTS FOR DOCUMENTATION
-- =============================================================================

COMMENT ON TABLE users IS 'User accounts with authentication and profile data. SOC 2 Control: CC6.1';
COMMENT ON TABLE roles IS 'Role definitions for RBAC. SOC 2 Control: CC6.2';
COMMENT ON TABLE permissions IS 'Permission definitions. SOC 2 Control: CC6.1';
COMMENT ON TABLE audit_logs IS 'Immutable audit trail for all system events. SOC 2 Control: CC7.2';
COMMENT ON TABLE tenants IS 'Multi-tenant isolation. SOC 2 Control: CC6.6';
COMMENT ON TABLE sessions IS 'User session management. SOC 2 Control: CC6.1';
COMMENT ON TABLE api_keys IS 'API key management. SOC 2 Control: CC6.1';

-- =============================================================================
-- DOWN MIGRATION (ROLLBACK)
-- =============================================================================
-- DROP TRIGGER IF EXISTS users_audit ON users;
-- DROP TRIGGER IF EXISTS users_updated_at ON users;
-- DROP TRIGGER IF EXISTS tenants_updated_at ON tenants;
-- DROP TRIGGER IF EXISTS roles_updated_at ON roles;
-- DROP FUNCTION IF EXISTS audit_users_changes();
-- DROP FUNCTION IF EXISTS update_updated_at();
-- DROP TABLE IF EXISTS api_keys;
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS user_roles;
-- DROP TABLE IF EXISTS role_permissions;
-- DROP TABLE IF EXISTS permissions;
-- DROP TABLE IF EXISTS roles;
-- DROP TABLE IF EXISTS audit_logs;
-- DROP TABLE IF EXISTS users;
-- DROP TABLE IF EXISTS tenants;
