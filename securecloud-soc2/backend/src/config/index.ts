/**
 * Application Configuration
 * SOC 2 Control: CC6.7 (Data Protection)
 * 
 * Centralized configuration management with environment variable validation.
 * Sensitive values are loaded from environment variables or secrets manager.
 */

import { z } from 'zod';

// Configuration schema with validation
const configSchema = z.object({
  env: z.enum(['development', 'staging', 'production']).default('development'),
  port: z.coerce.number().default(3000),
  
  // Database configuration - SOC 2 Control: CC6.7
  database: z.object({
    host: z.string(),
    port: z.coerce.number().default(5432),
    name: z.string(),
    user: z.string(),
    password: z.string(),
    ssl: z.boolean().default(true),
    poolMin: z.coerce.number().default(2),
    poolMax: z.coerce.number().default(10),
  }),
  
  // Redis configuration
  redis: z.object({
    host: z.string(),
    port: z.coerce.number().default(6379),
    password: z.string().optional(),
    tls: z.boolean().default(true),
  }),
  
  // JWT configuration - SOC 2 Control: CC6.1
  jwt: z.object({
    secret: z.string().min(32),
    accessTokenExpiry: z.string().default('15m'),
    refreshTokenExpiry: z.string().default('7d'),
    issuer: z.string().default('securecloud'),
    audience: z.string().default('securecloud-api'),
  }),
  
  // Encryption configuration - SOC 2 Control: CC6.7
  encryption: z.object({
    algorithm: z.string().default('aes-256-gcm'),
    keyId: z.string(),
    kmsRegion: z.string().default('us-east-1'),
  }),
  
  // CORS configuration - SOC 2 Control: CC6.6
  cors: z.object({
    allowedOrigins: z.array(z.string()),
  }),
  
  // Logging configuration - SOC 2 Control: CC7.2
  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
    format: z.enum(['json', 'pretty']).default('json'),
  }),
  
  // Rate limiting - SOC 2 Control: A1.1
  rateLimit: z.object({
    windowMs: z.coerce.number().default(900000), // 15 minutes
    maxRequests: z.coerce.number().default(100),
  }),
  
  // Session configuration - SOC 2 Control: CC6.1
  session: z.object({
    timeout: z.coerce.number().default(900), // 15 minutes
    maxConcurrent: z.coerce.number().default(5),
  }),
  
  // MFA configuration - SOC 2 Control: CC6.1
  mfa: z.object({
    issuer: z.string().default('SecureCloud'),
    window: z.coerce.number().default(1),
  }),
});

type Config = z.infer<typeof configSchema>;

// Load and validate configuration
const loadConfig = (): Config => {
  const rawConfig = {
    env: process.env.NODE_ENV,
    port: process.env.PORT,
    
    database: {
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT,
      name: process.env.DB_NAME || 'securecloud',
      user: process.env.DB_USER || 'securecloud',
      password: process.env.DB_PASSWORD || '',
      ssl: process.env.DB_SSL !== 'false',
      poolMin: process.env.DB_POOL_MIN,
      poolMax: process.env.DB_POOL_MAX,
    },
    
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD,
      tls: process.env.REDIS_TLS !== 'false',
    },
    
    jwt: {
      secret: process.env.JWT_SECRET || 'development-secret-change-in-production',
      accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY,
      refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY,
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    },
    
    encryption: {
      algorithm: process.env.ENCRYPTION_ALGORITHM,
      keyId: process.env.KMS_KEY_ID || 'local-dev-key',
      kmsRegion: process.env.AWS_REGION,
    },
    
    cors: {
      allowedOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(','),
    },
    
    logging: {
      level: process.env.LOG_LEVEL,
      format: process.env.LOG_FORMAT,
    },
    
    rateLimit: {
      windowMs: process.env.RATE_LIMIT_WINDOW,
      maxRequests: process.env.RATE_LIMIT_MAX,
    },
    
    session: {
      timeout: process.env.SESSION_TIMEOUT,
      maxConcurrent: process.env.SESSION_MAX_CONCURRENT,
    },
    
    mfa: {
      issuer: process.env.MFA_ISSUER,
      window: process.env.MFA_WINDOW,
    },
  };

  const result = configSchema.safeParse(rawConfig);
  
  if (!result.success) {
    console.error('Configuration validation failed:', result.error.format());
    throw new Error('Invalid configuration');
  }
  
  return result.data;
};

export const config = loadConfig();
export type { Config };
