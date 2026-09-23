import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { JwtService } from '@nestjs/jwt';
import { TokenService } from './token.service.js';

describe('TokenService', () => {
  let tokenService: TokenService;
  let jwtService: JwtService;
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.JWT_ACCESS_SECRET = 'test-dummy-access-secret-32-characters-long';
    process.env.JWT_ACCESS_EXPIRES_IN = '15m';
    process.env.JWT_REFRESH_EXPIRES_IN = '7d';

    jwtService = new JwtService();
    tokenService = new TokenService(jwtService);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Access Token Creation & Validation', () => {
    it('1. Access token is generated successfully', () => {
      const payload = {
        sub: 'user-uuid-123',
        email: 'student@phoenix.edu',
        role: 'STUDENT',
      };
      const token = tokenService.generateAccessToken(payload);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    it('2. Access token contains: sub, email, role', () => {
      const payload = {
        sub: 'user-uuid-123',
        email: 'faculty@phoenix.edu',
        role: 'FACULTY',
      };
      const token = tokenService.generateAccessToken(payload);
      const decoded = tokenService.verifyAccessToken(token);

      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.email).toBe(payload.email);
      expect(decoded.role).toBe(payload.role);
    });

    it('3. Access token uses configured secret', () => {
      const payload = {
        sub: 'admin-uuid-123',
        email: 'admin@phoenix.edu',
        role: 'ADMIN',
      };
      const token = tokenService.generateAccessToken(payload);

      // Verifying with correct secret succeeds
      expect(() =>
        jwtService.verify(token, {
          secret: 'test-dummy-access-secret-32-characters-long',
        }),
      ).not.toThrow();

      // Verifying with different secret fails
      expect(() =>
        jwtService.verify(token, {
          secret: 'wrong-secret-key-that-should-fail',
        }),
      ).toThrow();
    });

    it('4. Access token expires according to configured access expiration', () => {
      process.env.JWT_ACCESS_EXPIRES_IN = '15m';
      const payload = {
        sub: 'user-uuid-123',
        email: 'student@phoenix.edu',
        role: 'STUDENT',
      };
      const token = tokenService.generateAccessToken(payload);
      const decoded = tokenService.verifyAccessToken(token);

      const diffSeconds = decoded.exp - decoded.iat;
      // 15 minutes = 900 seconds
      expect(diffSeconds).toBe(900);
    });

    it('Fails clearly if JWT_ACCESS_SECRET is missing', () => {
      delete process.env.JWT_ACCESS_SECRET;
      const payload = {
        sub: 'user-uuid-123',
        email: 'student@phoenix.edu',
        role: 'STUDENT',
      };
      expect(() => tokenService.generateAccessToken(payload)).toThrow(
        'JWT_ACCESS_SECRET is not configured.',
      );
    });
  });

  describe('Refresh Token Generation & Hashing', () => {
    it('5. Refresh token generation produces a secure random value', () => {
      const token = tokenService.generateRefreshToken();
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      // 32 bytes hex encoded = 64 characters
      expect(token).toHaveLength(64);
      expect(/^[0-9a-f]{64}$/.test(token)).toBe(true);
    });

    it('6. Two generated refresh tokens are different', () => {
      const token1 = tokenService.generateRefreshToken();
      const token2 = tokenService.generateRefreshToken();
      expect(token1).not.toBe(token2);
    });

    it('7. Refresh token hashing is deterministic', () => {
      const token = tokenService.generateRefreshToken();
      const hash1 = tokenService.hashRefreshToken(token);
      const hash2 = tokenService.hashRefreshToken(token);
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    it('8. Raw refresh token is not equal to its SHA-256 hash', () => {
      const token = tokenService.generateRefreshToken();
      const hash = tokenService.hashRefreshToken(token);
      expect(token).not.toBe(hash);
    });

    it('9. A raw refresh token can be correctly matched against its stored hash', () => {
      const token = tokenService.generateRefreshToken();
      const hash = tokenService.hashRefreshToken(token);
      const isMatch = tokenService.compareRefreshToken(token, hash);
      expect(isMatch).toBe(true);
    });

    it('10. An incorrect refresh token does not match', () => {
      const token = tokenService.generateRefreshToken();
      const hash = tokenService.hashRefreshToken(token);
      const otherToken = tokenService.generateRefreshToken();
      const isMatch = tokenService.compareRefreshToken(otherToken, hash);
      expect(isMatch).toBe(false);
    });
  });

  describe('Refresh Token Expiration Calculation', () => {
    it('11. Calculates default 7d expiration correctly', () => {
      delete process.env.JWT_REFRESH_EXPIRES_IN;
      expect(tokenService.getRefreshTokenExpiresIn()).toBe('7d');
      expect(tokenService.getRefreshTokenExpiresInMs()).toBe(
        7 * 24 * 60 * 60 * 1000,
      );

      const before = Date.now();
      const expiresAt = tokenService.getRefreshTokenExpiresAt();
      const after = Date.now();

      expect(expiresAt.getTime()).toBeGreaterThanOrEqual(
        before + 7 * 24 * 60 * 60 * 1000,
      );
      expect(expiresAt.getTime()).toBeLessThanOrEqual(
        after + 7 * 24 * 60 * 60 * 1000,
      );
    });

    it('12. Calculates configured duration such as 30d correctly', () => {
      process.env.JWT_REFRESH_EXPIRES_IN = '30d';
      expect(tokenService.getRefreshTokenExpiresInMs()).toBe(
        30 * 24 * 60 * 60 * 1000,
      );

      const before = Date.now();
      const expiresAt = tokenService.getRefreshTokenExpiresAt();
      const after = Date.now();

      expect(expiresAt.getTime()).toBeGreaterThanOrEqual(
        before + 30 * 24 * 60 * 60 * 1000,
      );
      expect(expiresAt.getTime()).toBeLessThanOrEqual(
        after + 30 * 24 * 60 * 60 * 1000,
      );
    });

    it('13. Supports 24h and 30m durations correctly', () => {
      process.env.JWT_REFRESH_EXPIRES_IN = '24h';
      expect(tokenService.getRefreshTokenExpiresInMs()).toBe(
        24 * 60 * 60 * 1000,
      );

      process.env.JWT_REFRESH_EXPIRES_IN = '30m';
      expect(tokenService.getRefreshTokenExpiresInMs()).toBe(
        30 * 60 * 1000,
      );
    });
  });
});
