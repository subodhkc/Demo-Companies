import dotenv from 'dotenv';

dotenv.config();

export const config = {
  app: {
    name: process.env.APP_NAME || 'TechCorp AI Platform',
    version: process.env.APP_VERSION || '2.8.0',
    env: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT || '8080', 10),
  },
  
  database: {
    url: process.env.DATABASE_URL || '',
    pool: {
      min: parseInt(process.env.DATABASE_POOL_MIN || '10', 10),
      max: parseInt(process.env.DATABASE_POOL_MAX || '50', 10),
    },
    ssl: process.env.DATABASE_SSL === 'true',
  },
  
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    tls: process.env.REDIS_TLS === 'true',
    password: process.env.REDIS_PASSWORD,
  },
  
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    s3Bucket: process.env.AWS_S3_BUCKET || 'techcorp-customer-data',
    kmsKeyId: process.env.AWS_KMS_KEY_ID,
  },
  
  secrets: {
    enabled: process.env.SECRETS_MANAGER_ENABLED === 'true',
    databaseSecretArn: process.env.DATABASE_SECRET_ARN,
    apiKeysSecretArn: process.env.API_KEYS_SECRET_ARN,
  },
  
  security: {
    jwtSecret: process.env.JWT_SECRET || 'change-me-in-production',
    jwtExpiry: process.env.JWT_EXPIRY || '24h',
    encryptionKey: process.env.ENCRYPTION_KEY || 'change-me-in-production',
    sessionSecret: process.env.SESSION_SECRET || 'change-me-in-production',
    mfaIssuer: process.env.MFA_ISSUER || 'TechCorp AI',
  },
  
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  },
  
  cors: {
    origin: process.env.CORS_ORIGIN || 'https://app.techcorp-ai.com',
    credentials: process.env.CORS_CREDENTIALS === 'true',
  },
  
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.LOG_FORMAT || 'json',
    datadog: {
      apiKey: process.env.DATADOG_API_KEY,
      appKey: process.env.DATADOG_APP_KEY,
    },
  },
  
  monitoring: {
    sentry: {
      dsn: process.env.SENTRY_DSN,
      environment: process.env.SENTRY_ENVIRONMENT || 'production',
      tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE || '0.1'),
    },
  },
  
  openai: {
    apiKey: process.env.OPENAI_API_KEY,
    orgId: process.env.OPENAI_ORG_ID,
    model: process.env.OPENAI_MODEL || 'gpt-4-turbo-preview',
  },
  
  email: {
    smtp: {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      user: process.env.SMTP_USER,
      password: process.env.SMTP_PASSWORD,
      from: process.env.SMTP_FROM || 'noreply@techcorp-ai.com',
    },
  },
  
  features: {
    mfa: process.env.ENABLE_MFA === 'true',
    aiFeatures: process.env.ENABLE_AI_FEATURES === 'true',
    analytics: process.env.ENABLE_ANALYTICS === 'true',
    auditLogging: process.env.ENABLE_AUDIT_LOGGING === 'true',
  },
  
  compliance: {
    soc2Mode: process.env.SOC2_MODE === 'enabled',
    gdprMode: process.env.GDPR_MODE === 'enabled',
    dataResidencyEnforcement: process.env.DATA_RESIDENCY_ENFORCEMENT === 'true',
    auditLogRetentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '365', 10),
  },
  
  performance: {
    cacheTTL: parseInt(process.env.CACHE_TTL || '3600', 10),
    maxUploadSize: parseInt(process.env.MAX_UPLOAD_SIZE || '10485760', 10),
    requestTimeout: parseInt(process.env.REQUEST_TIMEOUT || '30000', 10),
  },
  
  multiTenancy: {
    isolation: process.env.TENANT_ISOLATION || 'strict',
    encryption: process.env.TENANT_ENCRYPTION === 'enabled',
  },
};

// Validate required configuration
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
];

if (config.app.env === 'production') {
  requiredEnvVars.forEach((envVar) => {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  });
}

export default config;
