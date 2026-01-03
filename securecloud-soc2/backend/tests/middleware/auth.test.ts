/**
 * Authentication Middleware Tests
 * SOC 2 Control: CC6.1 (Logical Access Security)
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import request from 'supertest';
import app from '../../src/index';
import { redis } from '../../src/services/redis';
import jwt from 'jsonwebtoken';

describe('Authentication Middleware', () => {
  const validToken = jwt.sign(
    {
      sub: 'user-123',
      email: 'test@securecloud.io',
      roles: ['developer'],
      permissions: ['data:read'],
      mfaVerified: true,
      sessionId: 'session-123',
      tenantId: 'tenant-123',
    },
    process.env.JWT_SECRET || 'test-secret',
    { expiresIn: '1h' }
  );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Token Validation', () => {
    it('should reject requests without authorization header', async () => {
      const response = await request(app)
        .get('/api/v1/users')
        .expect(401);

      expect(response.body.code).toBe('AUTH_TOKEN_MISSING');
    });

    it('should reject requests with invalid token format', async () => {
      const response = await request(app)
        .get('/api/v1/users')
        .set('Authorization', 'InvalidFormat token123')
        .expect(401);

      expect(response.body.code).toBe('AUTH_TOKEN_MISSING');
    });

    it('should reject expired tokens', async () => {
      const expiredToken = jwt.sign(
        { sub: 'user-123' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '-1h' }
      );

      const response = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body.code).toBe('AUTH_TOKEN_EXPIRED');
    });

    it('should reject blacklisted tokens', async () => {
      jest.spyOn(redis, 'get').mockResolvedValue('blacklisted');

      const response = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(401);

      expect(response.body.code).toBe('AUTH_TOKEN_REVOKED');
    });

    it('should accept valid tokens', async () => {
      jest.spyOn(redis, 'get').mockResolvedValue(null);
      jest.spyOn(redis, 'expire').mockResolvedValue(1);

      const response = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toBeDefined();
    });
  });

  describe('MFA Verification', () => {
    it('should require MFA for admin routes', async () => {
      const noMfaToken = jwt.sign(
        {
          sub: 'user-123',
          email: 'test@securecloud.io',
          roles: ['admin'],
          mfaVerified: false,
          sessionId: 'session-123',
          tenantId: 'tenant-123',
        },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      jest.spyOn(redis, 'get').mockResolvedValue('session-data');

      const response = await request(app)
        .get('/api/v1/admin/settings')
        .set('Authorization', `Bearer ${noMfaToken}`)
        .expect(403);

      expect(response.body.code).toBe('AUTH_MFA_REQUIRED');
    });
  });

  describe('Session Management', () => {
    it('should reject requests with expired sessions', async () => {
      jest.spyOn(redis, 'get').mockResolvedValue(null);

      const response = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(401);

      expect(response.body.code).toBe('AUTH_SESSION_EXPIRED');
    });

    it('should refresh session TTL on valid requests', async () => {
      const expireSpy = jest.spyOn(redis, 'expire').mockResolvedValue(1);
      jest.spyOn(redis, 'get').mockResolvedValue('session-data');

      await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(expireSpy).toHaveBeenCalled();
    });
  });
});
