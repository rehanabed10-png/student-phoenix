import { describe, it, expect, afterEach } from 'vitest';
import {
  REFRESH_TOKEN_COOKIE_NAME,
  getRefreshTokenCookieOptions,
  parseDurationToMs,
} from './cookies.util.js';

describe('CookiesUtil', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  describe('Cookie Configuration', () => {
    it('uses correct cookie name', () => {
      expect(REFRESH_TOKEN_COOKIE_NAME).toBe('phoenix_refresh_token');
    });

    it('enforces HttpOnly and SameSite strict', () => {
      const options = getRefreshTokenCookieOptions(604800000);

      expect(options.httpOnly).toBe(true);
      expect(options.sameSite).toBe('strict');
      expect(options.path).toBe('/api/auth');
      expect(options.maxAge).toBe(604800000);
    });

    it('secure production behavior: false in development, true in production', () => {
      process.env.NODE_ENV = 'development';
      const devOptions = getRefreshTokenCookieOptions(604800000);
      expect(devOptions.secure).toBe(false);

      process.env.NODE_ENV = 'production';
      const prodOptions = getRefreshTokenCookieOptions(604800000);
      expect(prodOptions.secure).toBe(true);
    });
  });

  describe('parseDurationToMs', () => {
    it('parses seconds, minutes, hours, and days correctly', () => {
      expect(parseDurationToMs('30s')).toBe(30 * 1000);
      expect(parseDurationToMs('15m')).toBe(15 * 60 * 1000);
      expect(parseDurationToMs('2h')).toBe(2 * 60 * 60 * 1000);
      expect(parseDurationToMs('7d')).toBe(7 * 24 * 60 * 60 * 1000);
    });

    it('defaults to 7 days if unparseable or undefined', () => {
      expect(parseDurationToMs(undefined)).toBe(7 * 24 * 60 * 60 * 1000);
      expect(parseDurationToMs('invalid')).toBe(7 * 24 * 60 * 60 * 1000);
    });
  });
});
