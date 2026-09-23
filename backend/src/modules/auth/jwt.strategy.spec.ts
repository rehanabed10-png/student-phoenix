import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { UnauthorizedException } from '@nestjs/common';
import { RoleName } from '@prisma/client';
import { JwtStrategy } from './jwt.strategy.js';
import type { AccessTokenPayload } from './token.service.js';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  const originalSecret = process.env.JWT_ACCESS_SECRET;

  beforeEach(() => {
    process.env.JWT_ACCESS_SECRET = 'test-jwt-secret-key-12345';
    strategy = new JwtStrategy();
  });

  afterEach(() => {
    process.env.JWT_ACCESS_SECRET = originalSecret;
  });

  describe('validate', () => {
    it('valid JWT payload produces the expected authenticated-user shape', async () => {
      const payload: AccessTokenPayload = {
        sub: 'user-uuid-123',
        email: 'student@phoenix.edu',
        role: RoleName.STUDENT,
      };

      const user = await strategy.validate(payload);

      expect(user).toEqual({
        id: 'user-uuid-123',
        email: 'student@phoenix.edu',
        role: RoleName.STUDENT,
      });
    });

    it('role is preserved correctly from the payload', async () => {
      const adminPayload: AccessTokenPayload = {
        sub: 'admin-uuid-456',
        email: 'admin@phoenix.edu',
        role: RoleName.ADMIN,
      };

      const user = await strategy.validate(adminPayload);

      expect(user.role).toBe(RoleName.ADMIN);
    });

    it('passwordHash is never returned in the authenticated user object', async () => {
      // Even if raw token payload somehow had passwordHash attached
      const taintedPayload: any = {
        sub: 'user-uuid-789',
        email: 'faculty@phoenix.edu',
        role: RoleName.FACULTY,
        passwordHash: '$argon2id$v=19$should-not-exist',
      };

      const user = await strategy.validate(taintedPayload);

      expect((user as any).passwordHash).toBeUndefined();
      expect(Object.keys(user)).toEqual(['id', 'email', 'role']);
    });

    it('throws UnauthorizedException when payload fields are missing', async () => {
      await expect(
        strategy.validate({ sub: '', email: 'test@phoenix.edu', role: 'STUDENT' } as any),
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        strategy.validate({ sub: '123', email: '', role: 'STUDENT' } as any),
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        strategy.validate({ sub: '123', email: 'test@phoenix.edu', role: '' } as any),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('secret resolution', () => {
    it('secret provider resolves the configured environment secret', () => {
      const secretProvider = (strategy as any)._secretOrKeyProvider;
      expect(secretProvider).toBeDefined();

      let resolvedSecret: string | undefined;
      secretProvider(null, null, (_err: any, secret: string) => {
        resolvedSecret = secret;
      });

      expect(resolvedSecret).toBe('test-jwt-secret-key-12345');
    });

    it('secret provider errors if JWT_ACCESS_SECRET is missing', () => {
      delete process.env.JWT_ACCESS_SECRET;
      const secretProvider = (strategy as any)._secretOrKeyProvider;

      let errorOccurred: any;
      secretProvider(null, null, (err: any) => {
        errorOccurred = err;
      });

      expect(errorOccurred).toBeInstanceOf(UnauthorizedException);
    });
  });
});
