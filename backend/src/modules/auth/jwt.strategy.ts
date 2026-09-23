import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { RoleName } from '@prisma/client';
import type { AccessTokenPayload } from './token.service.js';
import type { AuthenticatedUser } from './types/authenticated-user.js';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: (
        _request: unknown,
        _rawJwtToken: unknown,
        done: (err: any, secret?: string) => void,
      ) => {
        const secret = process.env.JWT_ACCESS_SECRET;
        if (!secret || secret.trim() === '') {
          return done(
            new UnauthorizedException('JWT access secret is not configured.'),
          );
        }
        return done(null, secret);
      },
    });
  }

  /**
   * Validates the decoded JWT payload.
   * Derives request.user identity purely from payload without database queries.
   */
  async validate(payload: AccessTokenPayload): Promise<AuthenticatedUser> {
    if (!payload?.sub || !payload?.email || !payload?.role) {
      throw new UnauthorizedException('Invalid access token payload.');
    }

    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role as RoleName,
    };
  }
}
