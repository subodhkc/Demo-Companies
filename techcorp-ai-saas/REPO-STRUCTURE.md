# TechCorp AI Repository Structure

This is a complete, production-ready Node.js/TypeScript SaaS application repository with enterprise-grade security, compliance, and infrastructure.

## Directory Structure

```
techcorp-ai-saas/
├── .github/
│   └── workflows/
│       └── ci.yml                    # CI/CD pipeline with security scanning
├── docs/
│   ├── COMPLIANCE.md                 # SOC 2, ISO 27001, GDPR, ISO 42001
│   ├── MIGRATIONS.md                 # Database migration history
│   ├── INFRASTRUCTURE.md             # AWS architecture and IaC
│   ├── INCIDENT-RESPONSE.md          # IR procedures and metrics
│   └── ACCESS-CONTROL.md             # RBAC, PAM, MFA policies
├── src/
│   ├── config/
│   │   └── index.ts                  # Application configuration
│   ├── middleware/
│   │   ├── auth.ts                   # JWT authentication
│   │   ├── tenantIsolation.ts        # Multi-tenant isolation
│   │   ├── auditLogger.ts            # Audit logging
│   │   └── errorHandler.ts           # Error handling
│   ├── services/
│   │   └── encryption.service.ts     # AES-256-GCM encryption
│   ├── routes/
│   │   └── index.ts                  # API routes
│   ├── utils/
│   │   └── logger.ts                 # Winston logger
│   └── index.ts                      # Application entry point
├── tests/
│   ├── middleware/
│   │   └── auth.test.ts              # Auth middleware tests
│   └── setup.ts                      # Test configuration
├── terraform/
│   ├── main.tf                       # Infrastructure as Code
│   └── variables.tf                  # Terraform variables
├── .dockerignore                     # Docker ignore patterns
├── .env.example                      # Environment variables template
├── .eslintrc.json                    # ESLint configuration
├── .gitignore                        # Git ignore patterns
├── CHANGELOG.md                      # Version history with security updates
├── Dockerfile                        # Multi-stage production build
├── docker-compose.yml                # Local development environment
├── jest.config.js                    # Jest test configuration
├── package.json                      # Dependencies and scripts
├── README.md                         # Project overview
├── SECURITY.md                       # Security policy and controls
├── tsconfig.json                     # TypeScript configuration
└── DEMO-REPO-GUIDE.md               # How to use this repo for reports

```

## Technology Stack

### Backend
- **Runtime**: Node.js 20.x LTS
- **Language**: TypeScript 5.3+
- **Framework**: Express.js 4.18+
- **Database**: PostgreSQL 15.3
- **Cache**: Redis 7.0
- **ORM**: Knex.js (migrations)

### Security
- **Authentication**: JWT with bcrypt
- **Encryption**: AES-256-GCM
- **Secrets**: AWS Secrets Manager
- **MFA**: TOTP (Google Authenticator compatible)
- **Rate Limiting**: express-rate-limit
- **Headers**: Helmet.js
- **Input Validation**: Joi

### Infrastructure
- **Cloud**: AWS (ECS Fargate, RDS, ElastiCache, S3)
- **IaC**: Terraform
- **Containers**: Docker
- **Orchestration**: ECS with Fargate
- **CDN**: CloudFront
- **WAF**: AWS WAF with OWASP rules

### Monitoring
- **Logging**: Winston + CloudWatch
- **APM**: DataDog
- **Errors**: Sentry
- **Metrics**: Prometheus + CloudWatch

### CI/CD
- **Pipeline**: GitHub Actions
- **Security Scanning**: Snyk, Trivy, Semgrep
- **Testing**: Jest, Supertest, Playwright
- **Deployment**: Blue-Green via ECS

## Key Features

### Security Controls
1. **Authentication & Authorization**
   - JWT-based authentication
   - Role-based access control (RBAC)
   - Multi-factor authentication (MFA)
   - Session management with timeout

2. **Data Protection**
   - Encryption at rest (AES-256)
   - Encryption in transit (TLS 1.3)
   - Customer-managed encryption keys
   - Data classification framework

3. **Multi-Tenancy**
   - Strict tenant isolation
   - Row-level security
   - Tenant-specific encryption
   - Separate database schemas

4. **Audit & Compliance**
   - Comprehensive audit logging
   - Immutable audit trail
   - Compliance reporting
   - SOC 2, ISO 27001, GDPR ready

5. **Network Security**
   - Zero-trust architecture
   - Network segmentation
   - WAF with OWASP rules
   - DDoS protection

### Development Features
1. **Code Quality**
   - TypeScript strict mode
   - ESLint with security plugin
   - Prettier formatting
   - Pre-commit hooks

2. **Testing**
   - Unit tests (Jest)
   - Integration tests
   - E2E tests (Playwright)
   - 80%+ code coverage

3. **CI/CD**
   - Automated testing
   - Security scanning
   - Container scanning
   - Blue-green deployment

## Getting Started

### Prerequisites
- Node.js 20.x or higher
- PostgreSQL 15.x
- Redis 7.x
- Docker (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/techcorp-ai/platform.git
cd platform

# Install dependencies
npm ci

# Copy environment variables
cp .env.example .env

# Run database migrations
npm run db:migrate

# Start development server
npm run dev
```

### Docker Development

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Running Tests

```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e

# Coverage report
npm test -- --coverage
```

### Security Scanning

```bash
# Dependency audit
npm run security:scan

# Fix vulnerabilities
npm run security:fix

# Container scan
npm run docker:scan
```

## Deployment

### Staging
```bash
npm run deploy:staging
```

### Production
```bash
npm run deploy:production
```

## Compliance Evidence

This repository contains comprehensive documentation for compliance audits:

- **SOC 2**: Control implementation evidence in `docs/COMPLIANCE.md`
- **ISO 27001**: Annex A controls in `docs/COMPLIANCE.md`
- **GDPR**: Data protection measures in `docs/COMPLIANCE.md`
- **ISO 42001**: AI management system in `docs/COMPLIANCE.md`

## Architecture Highlights

### Multi-Tenant Isolation
- Database-level isolation with row-level security
- Tenant ID validation on every request
- Separate encryption keys per tenant
- Network-level isolation in production

### Security Layers
1. **Network**: VPC, security groups, WAF
2. **Application**: Authentication, authorization, input validation
3. **Data**: Encryption, access controls, audit logging
4. **Infrastructure**: IaC, immutable infrastructure, automated patching

### High Availability
- Multi-AZ deployment
- Auto-scaling
- Load balancing
- Automated failover
- 99.9% uptime SLA

## Contributing

See `CONTRIBUTING.md` for development guidelines.

## Security

See `SECURITY.md` for security policy and vulnerability reporting.

## License

Proprietary - All rights reserved.

## Contact

- **Engineering**: engineering@techcorp-ai.com
- **Security**: security@techcorp-ai.com
- **Support**: support@techcorp-ai.com
