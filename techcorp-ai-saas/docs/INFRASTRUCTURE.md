# Infrastructure Documentation

## Cloud Architecture

### AWS Services Used

#### Compute
- **ECS Fargate**: Container orchestration for microservices
  - 15 services running across 3 availability zones
  - Auto-scaling: 10-50 tasks per service
  - CPU: 2 vCPU per task
  - Memory: 4GB per task
  
- **Lambda**: Serverless functions for event processing
  - 25 functions deployed
  - Runtime: Node.js 20.x, Python 3.11
  - Concurrent executions: 100 reserved, 1000 burst

#### Database
- **RDS PostgreSQL 15.3**
  - Instance: db.r6g.2xlarge (Multi-AZ)
  - Storage: 500GB GP3, encrypted at rest
  - Backup: Daily automated, 30-day retention
  - Read replicas: 2 (one per region)
  
- **ElastiCache Redis 7.0**
  - Cluster mode enabled
  - 3 shards, 2 replicas per shard
  - Instance: cache.r6g.large
  - Encryption: In-transit and at-rest

#### Storage
- **S3 Buckets**
  - `techcorp-customer-data` (encrypted, versioning enabled)
  - `techcorp-backups` (encrypted, lifecycle policies)
  - `techcorp-logs` (encrypted, 90-day retention)
  - `techcorp-ml-models` (encrypted, versioning enabled)
  
- **EFS**: Shared file system for ML training data
  - Encrypted at rest
  - Automatic backups enabled
  - Performance mode: General Purpose

#### Networking
- **VPC**: 10.0.0.0/16
  - Public subnets: 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24
  - Private subnets: 10.0.11.0/24, 10.0.12.0/24, 10.0.13.0/24
  - Database subnets: 10.0.21.0/24, 10.0.22.0/24, 10.0.23.0/24
  
- **Application Load Balancer**
  - SSL/TLS termination (TLS 1.3)
  - WAF enabled with OWASP rules
  - Access logs to S3
  
- **CloudFront**: CDN for static assets
  - Custom SSL certificate
  - Geo-restriction enabled
  - DDoS protection via Shield Standard

#### Security
- **AWS WAF**: Web application firewall
  - OWASP Top 10 rules
  - Rate limiting: 2000 requests per 5 minutes per IP
  - Geo-blocking for high-risk countries
  
- **GuardDuty**: Threat detection
  - Enabled in all regions
  - Findings exported to Security Hub
  
- **Security Hub**: Centralized security findings
  - CIS AWS Foundations Benchmark
  - PCI DSS compliance checks
  
- **Secrets Manager**: Secrets and credentials
  - Automatic rotation enabled
  - Encryption with KMS
  
- **KMS**: Encryption key management
  - Customer-managed keys (CMK)
  - Automatic key rotation enabled
  - Separate keys per environment

#### Monitoring
- **CloudWatch**
  - Logs: 90-day retention
  - Metrics: Custom application metrics
  - Alarms: 50+ configured
  - Dashboards: 5 operational dashboards
  
- **X-Ray**: Distributed tracing
  - Enabled for all microservices
  - Sampling rate: 10%

#### CI/CD
- **CodePipeline**: Deployment automation
  - Source: GitHub
  - Build: CodeBuild
  - Deploy: ECS rolling update
  
- **CodeBuild**: Build automation
  - Docker image builds
  - Security scanning (Snyk, Trivy)
  - Unit and integration tests

---

## Infrastructure as Code

### Terraform Configuration

#### Directory Structure
```
terraform/
├── environments/
│   ├── production/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   └── development/
├── modules/
│   ├── vpc/
│   ├── ecs/
│   ├── rds/
│   ├── s3/
│   ├── security/
│   └── monitoring/
└── global/
    ├── iam/
    └── route53/
```

#### Key Modules

**VPC Module**
- Creates VPC with public, private, and database subnets
- NAT gateways in each AZ
- VPC flow logs enabled
- Network ACLs configured

**ECS Module**
- ECS cluster with Fargate capacity providers
- Task definitions with security best practices
- Service auto-scaling policies
- Load balancer integration

**RDS Module**
- Multi-AZ PostgreSQL instance
- Automated backups and snapshots
- Parameter groups with security hardening
- Subnet groups for database isolation

**Security Module**
- Security groups with least privilege
- WAF rules and IP sets
- KMS keys for encryption
- Secrets Manager integration

#### State Management
- **Backend**: S3 with DynamoDB locking
- **Encryption**: Server-side encryption enabled
- **Versioning**: Enabled for state files
- **Access**: Restricted to CI/CD and DevOps team

---

## Network Architecture

### Multi-Region Setup

#### Primary Region: us-east-1
- Production workloads
- Primary database (RDS Multi-AZ)
- Active-active load balancing

#### Secondary Region: us-west-2
- Disaster recovery
- Read replica database
- Standby capacity

#### EU Region: eu-west-1
- GDPR compliance (data residency)
- EU customer data processing
- Independent deployment

### Network Security

#### Security Groups
- **ALB-SG**: Ports 80, 443 from 0.0.0.0/0
- **ECS-SG**: Port 8080 from ALB-SG only
- **RDS-SG**: Port 5432 from ECS-SG only
- **Redis-SG**: Port 6379 from ECS-SG only

#### Network ACLs
- Deny all by default
- Explicit allow rules for required traffic
- Logging enabled for denied traffic

#### VPN Access
- AWS Client VPN for administrative access
- MFA required
- Certificate-based authentication
- IP allowlisting

---

## Deployment Architecture

### Blue-Green Deployment

#### Process
1. Deploy new version (green) alongside current (blue)
2. Run automated tests on green environment
3. Route 10% traffic to green for canary testing
4. Monitor metrics for 30 minutes
5. If successful, route 100% traffic to green
6. Keep blue environment for 24 hours for rollback
7. Terminate blue environment

#### Rollback Procedure
1. Route 100% traffic back to blue
2. Investigate issues in green
3. Fix and redeploy
4. Repeat process

### Container Orchestration

#### ECS Task Definition
```json
{
  "family": "techcorp-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "containerDefinitions": [{
    "name": "api",
    "image": "techcorp/api:latest",
    "portMappings": [{
      "containerPort": 8080,
      "protocol": "tcp"
    }],
    "environment": [
      {"name": "NODE_ENV", "value": "production"},
      {"name": "LOG_LEVEL", "value": "info"}
    ],
    "secrets": [
      {"name": "DATABASE_URL", "valueFrom": "arn:aws:secretsmanager:..."},
      {"name": "API_KEY", "valueFrom": "arn:aws:secretsmanager:..."}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/techcorp-api",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3
    }
  }]
}
```

---

## Disaster Recovery

### Backup Strategy

#### Database Backups
- **Automated**: Daily at 3:00 AM UTC
- **Retention**: 30 days
- **Manual snapshots**: Before major changes
- **Cross-region**: Replicated to us-west-2
- **Testing**: Monthly restore tests

#### Application Backups
- **Container images**: Stored in ECR with lifecycle policies
- **Configuration**: Versioned in Git
- **Secrets**: Backed up in Secrets Manager
- **Infrastructure**: Terraform state in S3

#### Data Backups
- **S3**: Versioning enabled, cross-region replication
- **EFS**: Daily AWS Backup jobs
- **Logs**: Archived to Glacier after 90 days

### Recovery Procedures

#### RTO/RPO Targets
- **Critical services**: RTO 4 hours, RPO 1 hour
- **Non-critical services**: RTO 24 hours, RPO 24 hours

#### Disaster Recovery Plan
1. Declare disaster (incident commander)
2. Assess scope and impact
3. Activate DR team
4. Failover to secondary region
5. Restore from backups if needed
6. Verify system functionality
7. Communicate with customers
8. Post-incident review

#### Failover Process
1. Update Route53 to point to us-west-2
2. Promote read replica to primary
3. Scale up capacity in us-west-2
4. Verify application functionality
5. Monitor for issues

---

## Monitoring and Alerting

### DataDog Integration

#### Metrics Collected
- Application performance (APM)
- Infrastructure metrics (CPU, memory, disk)
- Database performance (queries, connections)
- Custom business metrics
- Security events

#### Dashboards
- **Operations**: System health, uptime, errors
- **Security**: Failed logins, suspicious activity
- **Business**: User activity, revenue metrics
- **Compliance**: Audit log activity, access reviews

#### Alerts
- **Critical**: PagerDuty notification, SMS, phone call
- **High**: Slack notification, email
- **Medium**: Email only
- **Low**: Dashboard notification

### Log Aggregation

#### CloudWatch Logs
- Application logs from ECS
- Lambda function logs
- VPC flow logs
- CloudTrail audit logs

#### Log Retention
- **Audit logs**: 1 year in CloudWatch, 7 years in S3 Glacier
- **Application logs**: 90 days in CloudWatch
- **System logs**: 30 days in CloudWatch
- **Access logs**: 90 days in S3

---

## Security Hardening

### Container Security

#### Image Scanning
- Automated scanning with Trivy and Snyk
- Scan on push to ECR
- Block deployment if critical vulnerabilities found
- Weekly rescans of all images

#### Runtime Security
- Read-only root filesystem
- Non-root user (UID 1000)
- Minimal base images (Alpine Linux)
- No privileged containers
- Resource limits enforced

### Database Security

#### PostgreSQL Hardening
- SSL/TLS required for all connections
- Password complexity requirements
- Connection limits per user
- Query logging for audit
- Row-level security enabled
- Encryption at rest with KMS

#### Access Control
- Least privilege database users
- Separate users per service
- No shared credentials
- Automatic password rotation (90 days)

### Network Security

#### DDoS Protection
- AWS Shield Standard (automatic)
- CloudFront rate limiting
- WAF rate-based rules
- Geo-blocking for high-risk countries

#### Intrusion Detection
- GuardDuty enabled
- VPC flow log analysis
- Anomaly detection
- Automated response via Lambda

---

## Cost Optimization

### Current Monthly Costs (Production)
- **Compute (ECS)**: $4,200
- **Database (RDS)**: $2,800
- **Storage (S3, EFS)**: $1,200
- **Networking (Data transfer, ALB)**: $1,800
- **Monitoring (DataDog, CloudWatch)**: $800
- **Security (WAF, GuardDuty)**: $400
- **Total**: ~$11,200/month

### Optimization Strategies
- Reserved instances for predictable workloads
- Spot instances for batch processing
- S3 lifecycle policies to move to cheaper storage
- CloudFront caching to reduce origin requests
- Auto-scaling to match demand
- Right-sizing instances based on usage

---

## Compliance Controls

### Infrastructure Controls

#### CC6.6: Logical Access
- VPN required for administrative access
- MFA enforced for AWS console
- IAM roles with least privilege
- Session timeout after 30 minutes

#### CC6.7: Encryption
- Encryption at rest for all data stores
- TLS 1.3 for all communications
- KMS for key management
- Automatic key rotation

#### CC7.2: System Monitoring
- CloudWatch monitoring all resources
- DataDog APM for application performance
- GuardDuty for threat detection
- Automated alerting for anomalies

#### CC8.1: Change Management
- All changes via Terraform
- Peer review required for infrastructure changes
- Automated testing in staging
- Rollback procedures documented

---

## Contact Information
- **Infrastructure Team**: infrastructure@techcorp-ai.com
- **DevOps On-call**: +1-555-DEVOPS-1
- **AWS Support**: Enterprise support plan

**Last Updated**: December 15, 2025
