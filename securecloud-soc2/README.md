# SecureCloud Platform

**SOC 2 Type II Certified Cloud Infrastructure Platform**

A production-ready B2B SaaS platform demonstrating enterprise security controls, compliance frameworks, and audit evidence for SOC 2 certification.

## Repository Purpose

This repository serves as a **comprehensive SOC 2 evidence package** containing:

1. **Actual Code Files** - Backend, frontend, API, middleware with security controls
2. **Database Schemas** - Migrations with audit trails and encryption
3. **CI/CD Pipelines** - Security scanning, deployment logs, change management
4. **Infrastructure as Code** - Terraform with security configurations
5. **Policy Documents** - Security policies mapped to SOC 2 controls
6. **Audit Evidence** - Logs, reports, and compliance documentation

## Company Profile

| Attribute | Value |
|-----------|-------|
| **Company** | SecureCloud Inc. |
| **Industry** | Cloud Infrastructure / B2B SaaS |
| **Employees** | 127 |
| **Revenue** | $18.5M ARR |
| **Customers** | 340+ enterprise clients |
| **Founded** | 2019 |
| **Headquarters** | Austin, TX |

## SOC 2 Compliance Status

| Framework | Status | Audit Date | Auditor |
|-----------|--------|------------|---------|
| **SOC 2 Type II** | Certified | November 2025 | Deloitte |
| **ISO 27001:2022** | Certified | September 2025 | BSI |
| **GDPR** | Compliant | Ongoing | Internal |

### Trust Service Criteria Coverage

- **Security (CC1-CC9)**: 47 controls implemented
- **Availability (A1)**: 8 controls implemented
- **Processing Integrity (PI1)**: 6 controls implemented
- **Confidentiality (C1)**: 5 controls implemented
- **Privacy (P1-P8)**: 12 controls implemented

## Technology Stack

### Backend
- **Runtime**: Node.js 20 LTS
- **Framework**: Express.js 4.18
- **Language**: TypeScript 5.3
- **Database**: PostgreSQL 15.4
- **Cache**: Redis 7.2
- **Message Queue**: Apache Kafka

### Frontend
- **Framework**: React 18
- **Build Tool**: Vite
- **State Management**: Zustand
- **UI Components**: Radix UI + Tailwind CSS

### Infrastructure
- **Cloud**: AWS (Primary), GCP (DR)
- **Orchestration**: Kubernetes (EKS)
- **IaC**: Terraform
- **Secrets**: HashiCorp Vault

### Security Stack
- **Identity**: Okta SSO + MFA
- **WAF**: AWS WAF + Cloudflare
- **SIEM**: Splunk Enterprise
- **EDR**: CrowdStrike Falcon
- **Vulnerability Scanning**: Qualys, Snyk

## Repository Structure

```
securecloud-soc2/
├── backend/                    # Node.js/Express API server
│   ├── src/
│   │   ├── api/               # API routes and controllers
│   │   ├── middleware/        # Auth, audit, security middleware
│   │   ├── services/          # Business logic services
│   │   ├── models/            # Database models
│   │   └── utils/             # Utility functions
│   ├── tests/                 # Unit and integration tests
│   └── package.json
│
├── frontend/                   # React SPA
│   ├── src/
│   │   ├── components/        # UI components
│   │   ├── pages/             # Page components
│   │   ├── hooks/             # Custom React hooks
│   │   └── utils/             # Frontend utilities
│   └── package.json
│
├── database/                   # Database schemas and migrations
│   ├── migrations/            # Versioned migrations
│   ├── seeds/                 # Seed data
│   └── schema/                # Schema definitions
│
├── infrastructure/             # Infrastructure as Code
│   ├── terraform/             # AWS/GCP infrastructure
│   ├── kubernetes/            # K8s manifests
│   └── docker/                # Docker configurations
│
├── .github/                    # CI/CD pipelines
│   ├── workflows/             # GitHub Actions
│   └── CODEOWNERS             # Code ownership
│
├── docs/                       # Documentation
│   ├── policies/              # Security policies
│   ├── procedures/            # Operational procedures
│   ├── evidence/              # Audit evidence
│   └── runbooks/              # Incident runbooks
│
├── logs/                       # Sample audit logs
│   ├── ci-cd/                 # CI/CD execution logs
│   ├── security/              # Security event logs
│   └── access/                # Access audit logs
│
└── scripts/                    # Operational scripts
    ├── security/              # Security automation
    └── compliance/            # Compliance checks
```

## SOC 2 Evidence Mapping

This repository provides evidence for the following SOC 2 controls:

### CC1: Control Environment
- `docs/policies/CODE-OF-CONDUCT.md` - Ethics and integrity
- `backend/src/middleware/` - Technical control implementation

### CC2: Communication and Information
- `docs/policies/SECURITY-POLICY.md` - Security communication
- `logs/` - Information quality and audit trails

### CC3: Risk Assessment
- `docs/evidence/RISK-REGISTER.md` - Risk identification
- `.github/workflows/security-scan.yml` - Vulnerability scanning

### CC5: Control Activities
- `backend/src/middleware/auth.ts` - Authentication controls
- `backend/src/middleware/rbac.ts` - Authorization controls

### CC6: Logical and Physical Access
- `backend/src/middleware/auth.ts` - Authentication (CC6.1)
- `backend/src/services/accessControl.ts` - Access provisioning (CC6.2)
- `database/migrations/` - Access review evidence (CC6.4)
- `backend/src/services/encryption.ts` - Data protection (CC6.7)

### CC7: System Operations
- `.github/workflows/security-scan.yml` - Vulnerability management (CC7.1)
- `backend/src/middleware/auditLogger.ts` - Anomaly detection (CC7.2)
- `docs/procedures/INCIDENT-RESPONSE.md` - Incident response (CC7.3)

### CC8: Change Management
- `.github/workflows/ci.yml` - Change control pipeline
- `logs/ci-cd/` - Change execution logs
- `database/migrations/` - Database change history

### CC9: Risk Mitigation
- `docs/evidence/VENDOR-ASSESSMENTS.md` - Vendor management
- `infrastructure/terraform/` - Business continuity

### A1: Availability
- `infrastructure/terraform/` - Capacity management
- `database/migrations/` - Backup procedures

## Quick Start

```bash
# Clone repository
git clone https://github.com/securecloud/platform.git
cd platform

# Install dependencies
npm run install:all

# Set up environment
cp .env.example .env

# Run database migrations
npm run db:migrate

# Start development servers
npm run dev
```

## Security Controls in Code

### Authentication (CC6.1)
```typescript
// backend/src/middleware/auth.ts
- JWT token validation
- MFA enforcement
- Session management
- Rate limiting
```

### Audit Logging (CC7.2)
```typescript
// backend/src/middleware/auditLogger.ts
- Request/response logging
- User action tracking
- Security event capture
- Immutable audit trail
```

### Encryption (CC6.7)
```typescript
// backend/src/services/encryption.ts
- AES-256-GCM encryption
- Key rotation
- Secure key storage
- Data classification
```

## Compliance Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Uptime | 99.9% | 99.99% |
| MTTD | <5 min | 4 min |
| MTTR | <15 min | 12 min |
| Vulnerability SLA | 24h critical | 100% met |
| Access Review | Quarterly | 100% complete |
| Security Training | Annual | 100% complete |

## Contact

- **Security Team**: security@securecloud.io
- **Compliance**: compliance@securecloud.io
- **Engineering**: engineering@securecloud.io

## License

Proprietary - All Rights Reserved
