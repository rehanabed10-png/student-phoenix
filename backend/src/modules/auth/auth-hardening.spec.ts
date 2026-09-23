import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
  ValidationPipe,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { RoleName, AuditEventType } from '@prisma/client';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { JwtStrategy } from './jwt.strategy.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { RolesGuard } from './guards/roles.guard.js';
import { ROLES_KEY } from './decorators/roles.decorator.js';
import { getRefreshTokenCookieOptions } from './utils/cookies.util.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { ForgotPasswordDto } from './dto/forgot-password.dto.js';
import { ResetPasswordDto } from './dto/reset-password.dto.js';
import type { PrismaService } from '../../common/prisma/prisma.service.js';
import type { UsersService } from '../users/users.service.js';
import type { AuditService } from '../audit/audit.service.js';

describe('Authentication Hardening & Session Security (Step 12)', () => {
  const validationPipe = new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  });

  // =========================================================================
  // 1. INPUT VALIDATION (Reject unknown/forged properties)
  // =========================================================================
  describe('Input Validation & Whitelisting Enforcement', () => {
    it('rejects forbidden/unexpected properties in RegisterDto (e.g. role tampering)', async () => {
      const forgedInput = {
        email: 'student@phoenix.edu',
        password: 'ValidPassword123!',
        firstName: 'John',
        lastName: 'Phoenix',
        role: 'ADMIN', // Attacker trying to self-assign ADMIN role
        isAdmin: true,
      };

      await expect(
        validationPipe.transform(forgedInput, {
          type: 'body',
          metatype: RegisterDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects unexpected properties in LoginDto', async () => {
      const forgedInput = {
        email: 'student@phoenix.edu',
        password: 'ValidPassword123!',
        rememberMe: true,
        extraToken: 'abc',
      };

      await expect(
        validationPipe.transform(forgedInput, {
          type: 'body',
          metatype: LoginDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects unexpected properties in ChangePasswordDto (e.g. userId injection)', async () => {
      const forgedInput = {
        currentPassword: 'CurrentPassword123!',
        newPassword: 'NewPassword123!',
        userId: 'victim-uuid-123', // Attacker trying to change someone else's password
      };

      await expect(
        validationPipe.transform(forgedInput, {
          type: 'body',
          metatype: ChangePasswordDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects unexpected properties in ForgotPasswordDto', async () => {
      const forgedInput = {
        email: 'student@phoenix.edu',
        redirectUrl: 'http://malicious-site.com', // Open redirect attempt
      };

      await expect(
        validationPipe.transform(forgedInput, {
          type: 'body',
          metatype: ForgotPasswordDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects unexpected properties in ResetPasswordDto', async () => {
      const forgedInput = {
        token: 'valid-reset-token-64chars',
        newPassword: 'BrandNewSecurePassword123!',
        email: 'admin@phoenix.edu',
        role: 'ADMIN',
      };

      await expect(
        validationPipe.transform(forgedInput, {
          type: 'body',
          metatype: ResetPasswordDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // =========================================================================
  // 2. TIMING SIDE-CHANNEL MITIGATION IN LOGIN
  // =========================================================================
  describe('Timing Attack Mitigation on Authentication', () => {
    let authService: AuthService;
    let mockPrisma: any;
    let mockUsersService: any;
    let mockPasswordService: any;
    let mockTokenService: any;
    let mockAuditService: any;

    beforeEach(() => {
      mockPrisma = {};
      mockUsersService = {
        findByEmail: vi.fn().mockResolvedValue(null), // Nonexistent user
      };
      mockPasswordService = {
        verify: vi.fn().mockResolvedValue(false),
      };
      mockTokenService = {};
      mockAuditService = {
        log: vi.fn().mockResolvedValue(undefined),
      };

      authService = new AuthService(
        mockPrisma as unknown as PrismaService,
        mockUsersService as unknown as UsersService,
        mockPasswordService as unknown as PasswordService,
        mockTokenService as unknown as TokenService,
        mockAuditService as unknown as AuditService,
      );
    });

    it('executes dummy hash verification when email does not exist to equalize response time', async () => {
      await expect(
        authService.login({
          email: 'nonexistent@phoenix.edu',
          password: 'AttemptPassword123!',
        }),
      ).rejects.toThrow(UnauthorizedException);

      // Verify that PasswordService.verify was still called with the dummy Argon2id hash
      expect(mockPasswordService.verify).toHaveBeenCalledWith(
        'AttemptPassword123!',
        expect.stringContaining('$argon2id$'),
      );
    });
  });

  // =========================================================================
  // 3. RATE LIMITING & SENSITIVE ENDPOINT THROTTLING
  // =========================================================================
  // =========================================================================
  // 3. RATE LIMITING & SENSITIVE ENDPOINT THROTTLING
  // =========================================================================
  describe('Endpoint-Specific Rate Limiting', () => {
    it('configures strict 15 req/min throttling on login route', () => {
      const limit = Reflect.getMetadata(
        'THROTTLER:LIMITdefault',
        AuthController.prototype.login,
      );
      const ttl = Reflect.getMetadata(
        'THROTTLER:TTLdefault',
        AuthController.prototype.login,
      );
      expect(limit).toBe(15);
      expect(ttl).toBe(60000);
    });

    it('configures strict 15 req/min throttling on forgot-password route', () => {
      const limit = Reflect.getMetadata(
        'THROTTLER:LIMITdefault',
        AuthController.prototype.forgotPassword,
      );
      const ttl = Reflect.getMetadata(
        'THROTTLER:TTLdefault',
        AuthController.prototype.forgotPassword,
      );
      expect(limit).toBe(15);
      expect(ttl).toBe(60000);
    });

    it('configures strict 15 req/min throttling on reset-password route', () => {
      const limit = Reflect.getMetadata(
        'THROTTLER:LIMITdefault',
        AuthController.prototype.resetPassword,
      );
      const ttl = Reflect.getMetadata(
        'THROTTLER:TTLdefault',
        AuthController.prototype.resetPassword,
      );
      expect(limit).toBe(15);
      expect(ttl).toBe(60000);
    });
  });

  // =========================================================================
  // 4. JWT INTEGRITY & GUARD VERIFICATION
  // =========================================================================
  describe('JWT Verification & Expiration Handling', () => {
    const testSecret = 'hardened-test-secret-at-least-32-bytes-long';
    let jwtService: JwtService;

    beforeEach(() => {
      process.env.JWT_ACCESS_SECRET = testSecret;
      jwtService = new JwtService();
    });

    it('rejects expired JWT token during guard/passport verification', () => {
      const expiredToken = jwtService.sign(
        {
          sub: 'user-uuid-1',
          email: 'student@phoenix.edu',
          role: RoleName.STUDENT,
        },
        {
          secret: testSecret,
          expiresIn: '-1s', // Token already expired
        },
      );

      // Verify that verifying an expired token throws TokenExpiredError
      expect(() =>
        jwtService.verify(expiredToken, { secret: testSecret }),
      ).toThrow();
    });

    it('rejects token with forged/tampered signature', () => {
      const forgedToken = jwtService.sign(
        {
          sub: 'admin-uuid',
          email: 'admin@phoenix.edu',
          role: RoleName.ADMIN,
        },
        {
          secret: 'wrong-secret-key-attacker',
          expiresIn: '15m',
        },
      );

      expect(() =>
        jwtService.verify(forgedToken, { secret: testSecret }),
      ).toThrow();
    });

    it('validates claims directly in JwtStrategy without database query', async () => {
      const strategy = new JwtStrategy();

      // Valid claims succeed
      const valid = await strategy.validate({
        sub: 'user-uuid-1',
        email: 'student@phoenix.edu',
        role: RoleName.STUDENT,
      });
      expect(valid).toEqual({
        id: 'user-uuid-1',
        email: 'student@phoenix.edu',
        role: RoleName.STUDENT,
      });

      // Missing sub throws
      await expect(
        strategy.validate({
          sub: '',
          email: 'student@phoenix.edu',
          role: RoleName.STUDENT,
        }),
      ).rejects.toThrow(UnauthorizedException);

      // Missing role throws
      await expect(
        strategy.validate({
          sub: 'user-uuid-1',
          email: 'student@phoenix.edu',
          role: '' as any,
        }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  // =========================================================================
  // 5. RBAC AUTHORIZATION (401 vs 403 Separation)
  // =========================================================================
  describe('RBAC RolesGuard Security', () => {
    let reflector: Reflector;
    let rolesGuard: RolesGuard;

    beforeEach(() => {
      reflector = new Reflector();
      rolesGuard = new RolesGuard(reflector);
    });

    function createMockContext(user: any, requiredRoles?: RoleName[]) {
      vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue(requiredRoles);
      return {
        getHandler: vi.fn(),
        getClass: vi.fn(),
        switchToHttp: () => ({
          getRequest: () => ({ user }),
        }),
      } as any;
    }

    it('returns 401 Unauthorized when request is unauthenticated', () => {
      const context = createMockContext(undefined, [RoleName.ADMIN]);

      expect(() => rolesGuard.canActivate(context)).toThrow(
        UnauthorizedException,
      );
    });

    it('returns 403 Forbidden when authenticated user lacks the required role', () => {
      const context = createMockContext(
        { id: 'user-1', email: 's@phoenix.edu', role: RoleName.STUDENT },
        [RoleName.ADMIN],
      );

      expect(() => rolesGuard.canActivate(context)).toThrow(ForbiddenException);
    });

    it('allows access when user possesses one of the required roles', () => {
      const context = createMockContext(
        { id: 'admin-1', email: 'a@phoenix.edu', role: RoleName.ADMIN },
        [RoleName.ADMIN, RoleName.FACULTY],
      );

      expect(rolesGuard.canActivate(context)).toBe(true);
    });
  });

  // =========================================================================
  // 6. COOKIE SECURITY ATTRIBUTES
  // =========================================================================
  describe('Refresh Cookie Security Configuration', () => {
    it('enforces HttpOnly, SameSite=Strict, and scoped /api/auth path', () => {
      const options = getRefreshTokenCookieOptions(7 * 24 * 60 * 60 * 1000);

      expect(options.httpOnly).toBe(true);
      expect(options.sameSite).toBe('strict');
      expect(options.path).toBe('/api/auth');
      expect(options.maxAge).toBe(7 * 24 * 60 * 60 * 1000);
    });

    it('enforces secure flag in production environment', () => {
      const prevEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        const options = getRefreshTokenCookieOptions(1000);
        expect(options.secure).toBe(true);
      } finally {
        process.env.NODE_ENV = prevEnv;
      }
    });
  });
});
