/**
 * SecureCloud Platform - Main Application Entry Point
 * SOC 2 Control: CC5.2 (Technology Controls)
 * 
 * This file initializes the Express application with all security
 * middleware and configurations required for SOC 2 compliance.
 */

import express, { Application } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';

import { config } from './config';
import { logger, morganStream } from './utils/logger';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { authMiddleware } from './middleware/auth';
import { auditLogger } from './middleware/auditLogger';
import { rbacMiddleware } from './middleware/rbac';
import { requestValidator } from './middleware/requestValidator';

import apiRoutes from './api/routes';
import healthRoutes from './api/health';

const app: Application = express();

// =============================================================================
// Security Middleware - SOC 2 Control: CC6.6 (System Boundaries)
// =============================================================================

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-site' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
}));

// CORS configuration - SOC 2 Control: CC6.6
app.use(cors({
  origin: config.cors.allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Correlation-ID'],
  exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
  credentials: true,
  maxAge: 86400, // 24 hours
}));

// Rate limiting - SOC 2 Control: A1.1 (Capacity Management)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'You have exceeded the rate limit. Please try again later.',
    retryAfter: 900,
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      path: req.path,
      userAgent: req.get('User-Agent'),
    });
    res.status(429).json({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
    });
  },
});
app.use('/api/', limiter);

// =============================================================================
// Request Processing Middleware
// =============================================================================

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging - SOC 2 Control: CC7.2 (Anomaly Detection)
app.use(morgan('combined', { stream: morganStream }));

// Audit logging for all requests - SOC 2 Control: CC7.2
app.use(auditLogger);

// Request validation - SOC 2 Control: CC5.2
app.use(requestValidator);

// =============================================================================
// Routes
// =============================================================================

// Health check routes (no auth required)
app.use('/health', healthRoutes);

// API routes (auth required)
app.use('/api/v1', authMiddleware, rbacMiddleware, apiRoutes);

// =============================================================================
// Error Handling - SOC 2 Control: CC7.3 (Incident Response)
// =============================================================================

app.use(notFoundHandler);
app.use(errorHandler);

// =============================================================================
// Server Startup
// =============================================================================

const PORT = config.port || 3000;

const server = app.listen(PORT, () => {
  logger.info(`SecureCloud Platform API started`, {
    port: PORT,
    environment: config.env,
    nodeVersion: process.version,
    timestamp: new Date().toISOString(),
  });
});

// Graceful shutdown - SOC 2 Control: A1.3 (Disaster Recovery)
const gracefulShutdown = (signal: string) => {
  logger.info(`${signal} received. Starting graceful shutdown...`);
  
  server.close((err) => {
    if (err) {
      logger.error('Error during server shutdown', { error: err.message });
      process.exit(1);
    }
    
    logger.info('Server closed. Cleaning up resources...');
    
    // Close database connections, etc.
    process.exit(0);
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Forced shutdown due to timeout');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled rejection handler - SOC 2 Control: CC7.3
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});

// Uncaught exception handler - SOC 2 Control: CC7.3
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

export default app;
