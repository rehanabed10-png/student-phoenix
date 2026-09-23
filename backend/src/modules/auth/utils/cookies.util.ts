import type { CookieOptions } from 'express';

export const REFRESH_TOKEN_COOKIE_NAME = 'phoenix_refresh_token';

/**
 * Parses duration strings (e.g. '7d', '15m', '1h', '60s') into milliseconds.
 * Defaults to 7 days if the format is invalid or undefined.
 */
export function parseDurationToMs(duration?: string): number {
  if (!duration) {
    return 7 * 24 * 60 * 60 * 1000;
  }

  const match = duration.trim().match(/^(\d+)([smhd])$/);
  if (!match) {
    return 7 * 24 * 60 * 60 * 1000;
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      return value * 1000;
    case 'm':
      return value * 60 * 1000;
    case 'h':
      return value * 60 * 60 * 1000;
    case 'd':
      return value * 24 * 60 * 60 * 1000;
    default:
      return 7 * 24 * 60 * 60 * 1000;
  }
}

export function getRefreshTokenCookieOptions(maxAgeMs: number): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth',
    maxAge: maxAgeMs,
  };
}

/**
 * Generates options for clearing the refresh token cookie.
 * Matches path, secure, httpOnly, and sameSite of the issued cookie.
 */
export function getClearRefreshTokenCookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth',
  };
}

