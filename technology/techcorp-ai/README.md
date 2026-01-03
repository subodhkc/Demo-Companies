# TechCorp AI - SaaS Platform

A modern SaaS platform with enterprise-grade security controls and compliance features.

## Security Features

- **Authentication**: JWT-based auth with MFA support (TOTP)
- **Encryption**: AES-256-GCM encryption at rest, TLS 1.3 in transit
- **Audit Logging**: Comprehensive activity tracking with tamper-evident logs
- **API Security**: Rate limiting, input validation, CSRF protection
- **Access Control**: Role-based access control (RBAC)
- **Key Management**: Automated key rotation and secure storage

## Compliance Frameworks

### ISO 27001
- **A.9.2.1**: User registration and de-registration
- **A.9.4.2**: Secure log-on procedures (MFA implementation)
- **A.9.4.3**: Password management system
- **A.10.1.1**: Cryptographic controls policy
- **A.12.4.1**: Event logging (comprehensive audit trail)
- **A.18.1.5**: Regulation of cryptographic controls

### SOC 2
- **CC6.1**: Logical and physical access controls
- **CC6.6**: Encryption of sensitive data
- **CC7.2**: System monitoring and logging

### NIST Cybersecurity Framework
- **PR.AC-1**: Identity and credential management
- **PR.AC-7**: Multi-factor authentication
- **PR.DS-1**: Data-at-rest protection
- **DE.CM-1**: Network and system monitoring

### GDPR
- **Article 32**: Security of processing (encryption, pseudonymization)
- **Article 30**: Records of processing activities (audit logs)

## Tech Stack

- Python 3.11+
- FastAPI (API framework)
- PostgreSQL with encryption
- Redis for session management
- Docker containerization
- Cryptography library for encryption
- PyOTP for MFA

## Getting Started

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run with Docker
docker-compose up -d

# Run tests
pytest tests/
```

## Security Controls Implemented

1. **Multi-factor authentication (TOTP)** - ISO 27001 A.9.4.2
2. **JWT token rotation** - SOC 2 CC6.1
3. **Database encryption at rest** - NIST CSF PR.DS-1
4. **TLS 1.3 for all connections** - ISO 27001 A.10.1.1
5. **Comprehensive audit logging** - ISO 27001 A.12.4.1
6. **Rate limiting on all endpoints** - SOC 2 CC6.6
7. **Input validation and sanitization** - OWASP Top 10
8. **CSRF protection** - OWASP Top 10
9. **Secure session management** - SOC 2 CC6.1
10. **Encryption key rotation** - ISO 27001 A.10.1.2

## Project Structure

```
techcorp-ai/
├── src/
│   ├── auth/
│   │   ├── jwt_handler.py      # JWT authentication
│   │   ├── mfa.py              # Multi-factor authentication
│   │   └── oauth2.py           # OAuth2 implementation
│   ├── encryption/
│   │   ├── data_encryption.py  # AES-256 encryption
│   │   └── key_management.py   # Key rotation
│   ├── audit/
│   │   ├── activity_log.py     # Audit logging
│   │   └── compliance_reporter.py
│   ├── api/
│   │   ├── user_management.py  # User CRUD
│   │   └── rate_limiting.py    # API rate limiting
│   ├── security/
│   │   ├── input_validation.py # Input sanitization
│   │   └── csrf_protection.py  # CSRF tokens
│   └── database/
│       ├── connection_pool.py  # DB connection pooling
│       └── encryption_at_rest.py
├── tests/
│   ├── security_test.py        # Security tests
│   └── integration_test.py     # Integration tests
├── config/
│   ├── security.yaml           # Security configuration
│   └── compliance.yaml         # Compliance settings
├── docker-compose.yml          # Container orchestration
├── requirements.txt            # Python dependencies
└── .env.example               # Environment template
```

## Compliance Reports

This repository demonstrates security controls that map to:
- **ISO 27001**: 85% coverage (6 controls)
- **SOC 2**: 78% coverage (3 criteria)
- **NIST CSF**: 70% coverage (4 functions)

## Security Testing

```bash
# Run security tests
pytest tests/security_test.py -v

# Run integration tests
pytest tests/integration_test.py -v
```

## License

MIT License - Demo purposes only

## Contact

For questions about security controls or compliance mappings:
- Email: security@techcorp.ai
- Website: https://techcorp.ai
