import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'node:crypto';
import { parseDurationToMs } from './utils/cookies.util.js';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  role: string;
}

export interface DecodedAccessToken extends AccessTokenPayload {
  iat: number;
  exp: number;
}

@Injectable()
export class TokenService {
  constructor(private readonly jwtService: JwtService) {}

  /**
   * Generates a short-lived access JWT containing sub, email, and role.
   * Fails explicitly if JWT_ACCESS_SECRET is not configured.
   */
  generateAccessToken(payload: AccessTokenPayload): string {
    const secret = process.env.JWT_ACCESS_SECRET;
    if (!secret || secret.trim() === '') {
      throw new Error('JWT_ACCESS_SECRET is not configured.');
    }

    const expiresIn = (process.env.JWT_ACCESS_EXPIRES_IN || '15m') as `${number}m` | `${number}s` | `${number}h` | `${number}d`;

    return this.jwtService.sign(
      {
        sub: payload.sub,
        email: payload.email,
        role: payload.role,
      },
      {
        secret,
        expiresIn,
      },
    );
  }

  /**
   * Verifies and decodes an access JWT token.
   */
  verifyAccessToken(token: string): DecodedAccessToken {
    const secret = process.env.JWT_ACCESS_SECRET;
    if (!secret || secret.trim() === '') {
      throw new Error('JWT_ACCESS_SECRET is not configured.');
    }

    return this.jwtService.verify<DecodedAccessToken>(token, {
      secret,
    });
  }

  /**
   * Generates a cryptographically secure, random 64-character hex refresh token.
   * Uses Node's crypto.randomBytes. Never use Math.random().
   */
  generateRefreshToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Hashes a raw refresh token using SHA-256 before database storage.
   * Deterministic hashing ensures matching tokens produce identical digests.
   */
  hashRefreshToken(rawToken: string): string {
    return crypto.createHash('sha256').update(rawToken).digest('hex');
  }

  /**
   * Compares a raw refresh token against a stored SHA-256 hash using
   * timingSafeEqual to prevent timing attacks.
   */
  compareRefreshToken(rawToken: string, storedHash: string): boolean {
    if (!rawToken || !storedHash) {
      return false;
    }

    const computedHash = this.hashRefreshToken(rawToken);
    if (computedHash.length !== storedHash.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      Buffer.from(computedHash, 'utf8'),
      Buffer.from(storedHash, 'utf8'),
    );
  }

  /**
   * Returns configured access token expiration string (default: 15m).
   */
  getAccessTokenExpiresIn(): string {
    return process.env.JWT_ACCESS_EXPIRES_IN || '15m';
  }

  /**
   * Returns configured refresh token expiration string (default: 7d).
   */
  getRefreshTokenExpiresIn(): string {
    return process.env.JWT_REFRESH_EXPIRES_IN || '7d';
  }

  /**
   * Parses duration strings (e.g. '7d', '15d', '30d', '24h', '30m', '60s') into milliseconds.
   * Defaults to 7 days if undefined or unparseable.
   */
  parseDurationToMs(duration?: string): number {
    return parseDurationToMs(duration);
  }

  /**
   * Returns the refresh token expiration duration in milliseconds based on
   * JWT_REFRESH_EXPIRES_IN (default: 7d).
   */
  getRefreshTokenExpiresInMs(): number {
    return this.parseDurationToMs(this.getRefreshTokenExpiresIn());
  }

  /**
   * Returns the calculated expiration Date for a newly issued refresh token
   * based on JWT_REFRESH_EXPIRES_IN (default: 7d).
   */
  getRefreshTokenExpiresAt(): Date {
    return new Date(Date.now() + this.getRefreshTokenExpiresInMs());
  }
}
