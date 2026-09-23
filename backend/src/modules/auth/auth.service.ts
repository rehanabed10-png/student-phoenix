import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response } from 'express';
import { PrismaService } from '../../common/prisma/prisma.service.js';
import { UsersService } from '../users/users.service.js';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { AuthResponseDto } from './dto/auth-response.dto.js';
import type { RefreshToken } from '@prisma/client';
import {
  REFRESH_TOKEN_COOKIE_NAME,
  getRefreshTokenCookieOptions,
  getClearRefreshTokenCookieOptions,
} from './utils/cookies.util.js';

export interface AuthenticationResult {
  authResponse: AuthResponseDto;
  rawRefreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
  ) {}

  /**
   * Registers a new student account, verifies password policy,
   * creates the user with the STUDENT role, and issues tokens.
   */
  async register(dto: RegisterDto): Promise<AuthenticationResult> {
    // Validate password policy
    const policyResult = this.passwordService.validatePolicy(dto.password);
    if (!policyResult.isValid) {
      throw new BadRequestException(policyResult.errors.join(' '));
    }

    // Hash password with Argon2id
    const passwordHash = await this.passwordService.hash(dto.password);

    // Create student user via UsersService (enforces STUDENT role, handles duplicates)
    const user = await this.usersService.createStudentUser({
      email: dto.email,
      passwordHash,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });

    // Generate tokens and persist refresh session
    return this.createAuthSession(user);
  }

  /**
   * Authenticates a user by email and password, issuing access and refresh tokens.
   * Generic error message prevents account enumeration.
   */
  async login(dto: LoginDto): Promise<AuthenticationResult> {
    const normalizedEmail = dto.email.toLowerCase().trim();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    const isPasswordValid = await this.passwordService.verify(
      dto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    return this.createAuthSession(user);
  }

  /**
   * Refreshes access and refresh tokens using an existing raw refresh token from HttpOnly cookie.
   * Performs atomic rotation, revoking the old token and generating a replacement.
   * Detects reuse attempts on previously rotated tokens and revokes the affected token chain.
   */
  async refresh(rawRefreshToken: string): Promise<AuthenticationResult> {
    if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
      throw new UnauthorizedException('Invalid or expired refresh token.');
    }

    const tokenHash = this.tokenService.hashRefreshToken(rawRefreshToken);
    const tokenRecord = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: { include: { role: true } } },
    });

    if (!tokenRecord) {
      throw new UnauthorizedException('Invalid or expired refresh token.');
    }

    // Token reuse detection: if token is already revoked and had a replacement issued
    if (tokenRecord.revokedAt != null) {
      if (tokenRecord.replacedByTokenId != null) {
        // Reuse of rotated token! Revoke the descendant token chain
        await this.prisma.$transaction(async (tx) => {
          await this.revokeTokenChain(tokenRecord.replacedByTokenId!, tx);
        });
      }
      throw new UnauthorizedException('Invalid or expired refresh token.');
    }

    // Expired token check
    if (tokenRecord.expiresAt <= new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token.');
    }

    // User existence check
    if (!tokenRecord.user) {
      throw new UnauthorizedException('Invalid or expired refresh token.');
    }

    // Generate new access token
    const accessToken = this.tokenService.generateAccessToken({
      sub: tokenRecord.user.id,
      email: tokenRecord.user.email,
      role: tokenRecord.user.role.name,
    });

    // Generate new refresh token
    const newRawRefreshToken = this.tokenService.generateRefreshToken();
    const newTokenHash = this.tokenService.hashRefreshToken(newRawRefreshToken);

    // Atomic rotation in transaction: create new record, revoke old record conditionally, and link replacement
    await this.prisma.$transaction(async (tx) => {
      const newRecord = await tx.refreshToken.create({
        data: {
          tokenHash: newTokenHash,
          userId: tokenRecord.user.id,
          expiresAt: this.tokenService.getRefreshTokenExpiresAt(),
        },
      });

      // Conditional state transition: only succeeds if the old token is STILL active
      const updateResult = await tx.refreshToken.updateMany({
        where: {
          id: tokenRecord.id,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
          replacedByTokenId: newRecord.id,
        },
      });

      if (updateResult.count !== 1) {
        throw new UnauthorizedException('Invalid or expired refresh token.');
      }
    });

    return {
      authResponse: {
        accessToken,
        user: this.usersService.sanitizeUser(tokenRecord.user),
      },
      rawRefreshToken: newRawRefreshToken,
    };
  }

  /**
   * Traverses and revokes all active tokens in the descendant chain starting from initialTokenId.
   */
  private async revokeTokenChain(
    initialTokenId: string,
    tx: any,
  ): Promise<void> {
    let currentTokenId: string | null = initialTokenId;
    const visited = new Set<string>();

    while (currentTokenId && !visited.has(currentTokenId)) {
      visited.add(currentTokenId);
      const descendant: RefreshToken | null =
        await tx.refreshToken.findUnique({
          where: { id: currentTokenId },
        });

      if (!descendant) {
        break;
      }

      if (!descendant.revokedAt) {
        await tx.refreshToken.update({
          where: { id: descendant.id },
          data: { revokedAt: new Date() },
        });
      }

      currentTokenId = descendant.replacedByTokenId;
    }
  }

  /**
   * Logs out the user by revoking the refresh token session if active.
   * Safe and idempotent: succeeds even if cookie is missing, unknown, or already revoked.
   */
  async logout(rawRefreshToken?: string): Promise<void> {
    if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
      return;
    }

    const tokenHash = this.tokenService.hashRefreshToken(rawRefreshToken);
    const tokenRecord = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
    });

    if (tokenRecord && !tokenRecord.revokedAt) {
      await this.prisma.refreshToken.update({
        where: { id: tokenRecord.id },
        data: { revokedAt: new Date() },
      });
    }
  }

  /**
   * Sets the HttpOnly refresh token cookie on the outgoing HTTP response.
   */
  setRefreshTokenCookie(res: Response, rawRefreshToken: string): void {
    const maxAgeMs = this.tokenService.getRefreshTokenExpiresInMs();
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      rawRefreshToken,
      getRefreshTokenCookieOptions(maxAgeMs),
    );
  }

  /**
   * Clears the HttpOnly refresh token cookie on the outgoing HTTP response.
   */
  clearRefreshTokenCookie(res: Response): void {
    res.clearCookie(
      REFRESH_TOKEN_COOKIE_NAME,
      getClearRefreshTokenCookieOptions(),
    );
  }

  /**
   * Internal helper: issues an access token and persists a hashed refresh token session.
   */
  private async createAuthSession(user: any): Promise<AuthenticationResult> {
    // Generate short-lived JWT access token
    const accessToken = this.tokenService.generateAccessToken({
      sub: user.id,
      email: user.email,
      role: user.role.name,
    });

    // Generate cryptographically secure refresh token
    const rawRefreshToken = this.tokenService.generateRefreshToken();
    const tokenHash = this.tokenService.hashRefreshToken(rawRefreshToken);

    // Store only the token hash in the database with configured expiration
    await this.prisma.refreshToken.create({
      data: {
        tokenHash,
        userId: user.id,
        expiresAt: this.tokenService.getRefreshTokenExpiresAt(),
      },
    });

    return {
      authResponse: {
        accessToken,
        user: this.usersService.sanitizeUser(user),
      },
      rawRefreshToken,
    };
  }
}
