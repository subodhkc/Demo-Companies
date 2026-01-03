import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { authMiddleware, requireRole, AuthRequest } from '../../src/middleware/auth';
import { config } from '../../src/config';

describe('Auth Middleware', () => {
  let mockRequest: Partial<AuthRequest>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      ip: '127.0.0.1',
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    nextFunction = jest.fn();
  });

  describe('authMiddleware', () => {
    it('should authenticate valid token', async () => {
      const token = jwt.sign(
        {
          userId: '123',
          email: 'test@example.com',
          tenantId: 'tenant-123',
          role: 'user',
        },
        config.security.jwtSecret
      );

      mockRequest.headers = {
        authorization: `Bearer ${token}`,
      };

      await authMiddleware(
        mockRequest as AuthRequest,
        mockResponse as Response,
        nextFunction
      );

      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.user?.id).toBe('123');
      expect(nextFunction).toHaveBeenCalled();
    });

    it('should reject missing authorization header', async () => {
      await authMiddleware(
        mockRequest as AuthRequest,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject invalid token', async () => {
      mockRequest.headers = {
        authorization: 'Bearer invalid-token',
      };

      await authMiddleware(
        mockRequest as AuthRequest,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    it('should allow access for authorized role', () => {
      mockRequest.user = {
        id: '123',
        email: 'test@example.com',
        tenantId: 'tenant-123',
        role: 'admin',
      };

      const middleware = requireRole(['admin']);
      middleware(
        mockRequest as AuthRequest,
        mockResponse as Response,
        nextFunction
      );

      expect(nextFunction).toHaveBeenCalled();
    });

    it('should deny access for unauthorized role', () => {
      mockRequest.user = {
        id: '123',
        email: 'test@example.com',
        tenantId: 'tenant-123',
        role: 'user',
      };

      const middleware = requireRole(['admin']);
      middleware(
        mockRequest as AuthRequest,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });
});
