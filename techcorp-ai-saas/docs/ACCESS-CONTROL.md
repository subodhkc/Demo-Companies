# Access Control Policy

## Role-Based Access Control (RBAC)

### Roles and Permissions

#### Admin Role
**Permissions:**
- Full system access
- User management (create, modify, delete)
- Configuration changes
- Access to all tenant data
- Audit log access
- Security settings management

**Assignment:**
- Requires VP-level approval
- Background check required
- Annual recertification
- MFA mandatory

**Current Admins:** 5 users

#### Developer Role
**Permissions:**
- Code repository access
- Development environment access
- Staging environment access (read-only production)
- Log viewing
- Deployment to non-production environments

**Assignment:**
- Manager approval required
- Secure coding training completion
- MFA mandatory

**Current Developers:** 45 users

#### Security Analyst Role
**Permissions:**
- Security tool access (SIEM, IDS/IPS)
- Audit log access (read-only)
- Incident response tools
- Vulnerability scanner access
- Security dashboard access

**Assignment:**
- Security team manager approval
- Security clearance required
- MFA mandatory

**Current Analysts:** 5 users

#### Customer Success Role
**Permissions:**
- Customer data access (assigned accounts only)
- Support ticket system
- Usage analytics (anonymized)
- Documentation access

**Assignment:**
- CS manager approval
- Customer data handling training
- MFA mandatory

**Current CS Team:** 12 users

#### Viewer Role
**Permissions:**
- Dashboard access (read-only)
- Documentation access
- Public reports access

**Assignment:**
- Any employee
- MFA recommended

**Current Viewers:** 8 users

### Access Request Process

1. **Request Submission**
   - Submit via ServiceNow
   - Specify role and justification
   - Manager approval required

2. **Security Review**
   - Automated background check
   - Compliance verification
   - Risk assessment

3. **Provisioning**
   - Automated via Okta
   - Just-in-time (JIT) access for temporary needs
   - Access logged in audit trail

4. **Confirmation**
   - Email notification to user
   - Manager notification
   - Security team notification for privileged access

### Access Review Process

#### Quarterly Reviews
- All access reviewed by managers
- Automated reports generated
- Unused access automatically revoked
- Exceptions documented and approved

#### Annual Recertification
- All privileged access recertified
- Training completion verified
- Background checks updated
- MFA compliance verified

### Privileged Access Management (PAM)

#### Privileged Accounts
- Production database access
- AWS root account
- Infrastructure admin access
- Encryption key access

#### Controls
- Break-glass procedures for emergencies
- Session recording for all privileged access
- Time-limited access (max 8 hours)
- Approval required for each session
- Automated alerts for privileged access

#### Break-Glass Procedure
1. Declare emergency (SEV-1 incident)
2. Incident commander approval
3. Access granted for 4 hours
4. All actions logged and reviewed
5. Post-incident review required

### Multi-Factor Authentication (MFA)

#### Requirements
- **Mandatory for:**
  - All admin access
  - Production environment access
  - Customer data access
  - VPN access
  - AWS console access

- **Recommended for:**
  - All employee accounts
  - Development environment access

#### Supported Methods
1. **TOTP** (Time-based One-Time Password)
   - Google Authenticator
   - Authy
   - Microsoft Authenticator

2. **Hardware Tokens**
   - YubiKey (provided to all admins)
   - Titan Security Key

3. **SMS** (backup only, not primary)

#### Enrollment
- Required within 7 days of account creation
- Backup codes provided (10 codes)
- Recovery process via IT helpdesk

### Session Management

#### Session Policies
- **Idle Timeout:** 30 minutes
- **Absolute Timeout:** 12 hours
- **Concurrent Sessions:** Max 3 per user
- **Session Binding:** IP address and device fingerprint

#### Session Security
- Secure cookie flags (HttpOnly, Secure, SameSite)
- Session token rotation on privilege escalation
- Logout on password change
- Automatic logout on suspicious activity

### Network Access Control

#### VPN Requirements
- Required for all administrative access
- Required for production database access
- Certificate-based authentication
- MFA required

#### IP Allowlisting
- Production access restricted to corporate IPs
- Exception process for remote work
- Temporary access for contractors (max 90 days)
- Automated expiration

#### Network Segmentation
- Production network isolated
- Development network separate
- DMZ for public-facing services
- Database network isolated

### API Access Control

#### API Keys
- Scoped to specific permissions
- Tenant-specific keys
- Automatic rotation every 90 days
- Rate limiting per key

#### OAuth 2.0
- Authorization code flow for user authentication
- Client credentials for service-to-service
- Token expiry: 1 hour (access), 30 days (refresh)
- Scope-based permissions

### Data Access Control

#### Data Classification
- **Critical:** PII, encryption keys, credentials
- **Confidential:** Customer data, business analytics
- **Internal:** System logs, metrics
- **Public:** Marketing materials, documentation

#### Access Rules
- Critical data: Admin role only, MFA required
- Confidential data: Role-based, MFA required
- Internal data: Employee access, authentication required
- Public data: No restrictions

#### Data Masking
- PII masked in non-production environments
- Credit card numbers: Last 4 digits only
- SSN: Last 4 digits only
- Email: Partial masking (u***@example.com)

### Third-Party Access

#### Vendor Access Policy
- Separate vendor accounts (no employee account sharing)
- Time-limited access (max 90 days)
- Specific scope and justification required
- Monitored and logged
- Quarterly vendor access review

#### Current Vendors with Access
1. **Mandiant** (Security consulting)
   - Access: Security tools, logs
   - Duration: Annual contract
   - Last review: November 2025

2. **AWS Support** (Infrastructure support)
   - Access: AWS console (read-only)
   - Duration: Ongoing
   - Last review: December 2025

3. **DataDog** (Monitoring)
   - Access: Metrics and logs (read-only)
   - Duration: Ongoing
   - Last review: October 2025

### Access Violations

#### Violation Types
- Unauthorized access attempts
- Privilege escalation attempts
- Data exfiltration attempts
- Policy violations (sharing credentials, etc.)
- Suspicious access patterns

#### Response
1. Automatic account suspension
2. Security team notification
3. Investigation initiated
4. Manager notification
5. HR involvement if policy violation
6. Termination for serious violations

### Access Metrics (2025)

#### Access Requests
- Total requests: 156
- Approved: 142 (91%)
- Denied: 14 (9%)
- Average approval time: 4 hours

#### Access Reviews
- Quarterly reviews completed: 4/4
- Accounts reviewed: 75
- Access revoked: 12 (unused access)
- Exceptions documented: 3

#### MFA Adoption
- Overall: 98% (73/75 users)
- Admin accounts: 100% (5/5)
- Developer accounts: 100% (45/45)
- Other roles: 92% (23/25)

#### Violations
- Unauthorized access attempts: 23 (all blocked)
- Shared credential incidents: 1 (user terminated)
- Suspicious access patterns: 8 (investigated, 0 confirmed threats)

### Compliance Mapping

#### SOC 2 Controls
- **CC6.1:** Logical and physical access controls
- **CC6.2:** Access authorization
- **CC6.3:** Access removal
- **CC6.6:** Logical access controls
- **CC6.7:** Access restriction

#### ISO 27001 Controls
- **A.9.1:** Business requirements for access control
- **A.9.2:** User access management
- **A.9.3:** User responsibilities
- **A.9.4:** System and application access control

#### GDPR Requirements
- **Article 32:** Security of processing
- **Article 25:** Data protection by design and default

**Last Updated:** December 15, 2025
**Next Review:** March 15, 2026
