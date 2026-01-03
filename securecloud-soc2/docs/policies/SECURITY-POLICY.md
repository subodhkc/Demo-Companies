# Information Security Policy

**Document ID**: POL-SEC-001  
**Version**: 3.2  
**Effective Date**: January 1, 2025  
**Owner**: Chief Information Security Officer (CISO)  
**Classification**: Internal

---

## 1. Purpose

This policy establishes the framework for protecting SecureCloud Inc.'s information assets, systems, and data in alignment with SOC 2 Trust Service Criteria.

## 2. Scope

This policy applies to all employees, contractors, and third parties with access to SecureCloud systems.

## 3. Security Controls

### 3.1 Access Control (CC6.1-CC6.4)

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| Authentication | MFA required for all access | Okta SSO + TOTP/Hardware keys |
| Password Policy | 14+ chars, complexity required | Enforced via Okta |
| Session Timeout | 15 minutes inactivity | Application-level enforcement |
| Access Reviews | Quarterly for all users | SailPoint automated reviews |

### 3.2 Data Protection (CC6.7)

| Data State | Encryption | Algorithm |
|------------|------------|-----------|
| At Rest | Required | AES-256-GCM |
| In Transit | Required | TLS 1.3 |
| Backups | Required | AES-256-GCM |

### 3.3 Logging and Monitoring (CC7.2)

- All authentication events logged
- All data access events logged
- Real-time alerting via Splunk SIEM
- 7-year log retention

## 4. Compliance

This policy supports SOC 2 Type II certification for Security, Availability, Processing Integrity, Confidentiality, and Privacy criteria.

## 5. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 3.2 | 2025-01-01 | Annual review |
| 3.1 | 2024-07-01 | Updated encryption standards |
| 3.0 | 2024-01-01 | SOC 2 Type II alignment |

---

**Approved by**: James Smith, CISO  
**Date**: January 1, 2025
