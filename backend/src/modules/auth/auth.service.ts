import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import type { Response } from 'express';
import { PrismaService } from '../../common/prisma/prisma.service.js';
import { UsersService } from '../users/users.service.js';
import { AuditService } from '../audit/audit.service.js';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { ForgotPasswordDto } from './dto/forgot-password.dto.js';
import { ResetPasswordDto } from './dto/reset-password.dto.js';
import { AuthResponseDto } from './dto/auth-response.dto.js';
import { AuditEventType, type RefreshToken } from '@prisma/client';
import {
  REFRESH_TOKEN_COOKIE_NAME,
  getRefreshTokenCookieOptions,
  getClearRefreshTokenCookieOptions,
} from './utils/cookies.util.js';

export interface AuthenticationResult {
  authResponse: AuthResponseDto;
  rawRefreshToken: string;
}

export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
}

// Constant Argon2id hash for timing side-channel mitigation on nonexistent email lookups
const DUMMY_ARGON2_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$dHVtbXlfc2FsdF9mb3JfdGltaW5n$aHNoQnV0Tm90VmFsaWRQYXNzd29yZA';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Helper that records an audit log event safely without failing the calling auth operation.
   */
  private async safeAudit(
    eventType: AuditEventType,
    data?: {
      userId?: string;
      email?: string;
      ipAddress?: string;
      userAgent?: string;
      metadata?: any;
    },
  ): Promise<void> {
    try {
      await this.auditService.log(eventType, data);
    } catch (error) {
      this.logger.error(
        `Failed to record audit event ${eventType}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Registers a new student account, verifies password policy,
   * creates the user with the STUDENT role, and issues tokens.
   */
  async register(
    dto: RegisterDto,
    context?: RequestContext,
  ): Promise<AuthenticationResult> {
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
    const session = await this.createAuthSession(user);

    await this.safeAudit(AuditEventType.REGISTER, {
      userId: user.id,
      email: user.email,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return session;
  }

  /**
   * Authenticates a user by email and password, issuing access and refresh tokens.
   * Generic error message prevents account enumeration.
   * Mitigates timing side-channel attacks by evaluating dummy hash on unknown email lookups.
   */
  async login(
    dto: LoginDto,
    context?: RequestContext,
  ): Promise<AuthenticationResult> {
    const normalizedEmail = dto.email.toLowerCase().trim();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      await this.passwordService.verify(dto.password, DUMMY_ARGON2_HASH);

      await this.safeAudit(AuditEventType.LOGIN_FAILURE, {
        email: normalizedEmail,
        ipAddress: context?.ipAddress,
        userAgent: context?.userAgent,
        metadata: { reason: 'invalid_credentials' },
      });
      throw new UnauthorizedException('Invalid email or password.');
    }

    const isPasswordValid = await this.passwordService.verify(
      dto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      await this.safeAudit(AuditEventType.LOGIN_FAILURE, {
        userId: user.id,
        email: user.email,
        ipAddress: context?.ipAddress,
        userAgent: context?.userAgent,
        metadata: { reason: 'invalid_credentials' },
      });
      throw new UnauthorizedException('Invalid email or password.');
    }

    const session = await this.createAuthSession(user);

    await this.safeAudit(AuditEventType.LOGIN_SUCCESS, {
      userId: user.id,
      email: user.email,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return session;
  }

  /**
   * Refreshes access and refresh tokens using an existing raw refresh token from HttpOnly cookie.
   * Performs atomic rotation, revoking the old token and generating a replacement.
   * Detects reuse attempts on previously rotated tokens and revokes the affected token chain.
   */
  async refresh(
    rawRefreshToken: string,
    context?: RequestContext,
  ): Promise<AuthenticationResult> {
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
      await this.safeAudit(AuditEventType.REFRESH_REUSE_DETECTED, {
        userId: tokenRecord.userId,
        ipAddress: context?.ipAddress,
        userAgent: context?.userAgent,
        metadata: { reason: 'revoked_refresh_token' },
      });

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

    await this.safeAudit(AuditEventType.REFRESH, {
      userId: tokenRecord.user.id,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
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
  async logout(
    rawRefreshToken?: string,
    context?: RequestContext,
  ): Promise<void> {
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

      await this.safeAudit(AuditEventType.LOGOUT, {
        userId: tokenRecord.userId,
        ipAddress: context?.ipAddress,
        userAgent: context?.userAgent,
      });
    }
  }

  /**
   * Authenticated password change.
   * Verifies current password, enforces password policy, verifies new password differs,
   * hashes the new password, and atomically updates passwordHash and revokes all active
   * refresh sessions for the user within a transaction.
   */
  async changePassword(
    userId: string,
    dto: ChangePasswordDto,
    context?: RequestContext,
  ): Promise<{ message: string }> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    const isCurrentPasswordValid = await this.passwordService.verify(
      dto.currentPassword,
      user.passwordHash,
    );

    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect.');
    }

    const policyResult = this.passwordService.validatePolicy(dto.newPassword);
    if (!policyResult.isValid) {
      throw new BadRequestException(policyResult.errors.join(' '));
    }

    if (dto.newPassword === dto.currentPassword) {
      throw new BadRequestException(
        'New password cannot be the same as the current password.',
      );
    }

    const newPasswordHash = await this.passwordService.hash(dto.newPassword);

    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { passwordHash: newPasswordHash },
      });

      await tx.refreshToken.updateMany({
        where: {
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
    });

    await this.safeAudit(AuditEventType.PASSWORD_CHANGE, {
      userId: user.id,
      email: user.email,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return { message: 'Password changed successfully.' };
  }

  /**
   * Generates a password reset token for the given email and records it in a hashed format.
   * Defends against account enumeration by returning a generic response whether or not the account exists.
   * Invalidates previously issued active reset tokens for the user atomically.
   */
  async requestPasswordReset(
    dto: ForgotPasswordDto,
    context?: RequestContext,
  ): Promise<{ message: string }> {
    const genericResponse = {
      message:
        'If an account exists for this email, a password reset link has been requested.',
    };

    const normalizedEmail = dto.email.toLowerCase().trim();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      return genericResponse;
    }

    const rawToken = this.tokenService.generatePasswordResetToken();
    const tokenHash = this.tokenService.hashPasswordResetToken(rawToken);
    const expiresAt = this.tokenService.getPasswordResetExpiresAt();

    // Atomic transaction: invalidate previous active reset tokens for this user and store new token hash
    await this.prisma.$transaction(async (tx) => {
      await tx.passwordResetToken.updateMany({
        where: {
          userId: user.id,
          usedAt: null,
        },
        data: {
          usedAt: new Date(),
        },
      });

      await tx.passwordResetToken.create({
        data: {
          tokenHash,
          userId: user.id,
          expiresAt,
        },
      });
    });

    await this.safeAudit(AuditEventType.PASSWORD_RESET_REQUEST, {
      userId: user.id,
      email: user.email,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return genericResponse;
  }

  /**
   * Resets the user password using a raw reset token.
   * Validates token existence, expiration, and unused status.
   * Performs an atomic state transition: updates user passwordHash, marks the reset token used
   * conditionally (usedAt: null concurrency guard), and revokes all active refresh tokens for the user.
   */
  async resetPassword(
    dto: ResetPasswordDto,
    context?: RequestContext,
  ): Promise<{ message: string }> {
    const tokenHash = this.tokenService.hashPasswordResetToken(dto.token);

    const resetTokenRecord = await this.prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!resetTokenRecord) {
      throw new UnauthorizedException(
        'Invalid or expired password reset token.',
      );
    }

    if (resetTokenRecord.usedAt !== null) {
      throw new UnauthorizedException(
        'Invalid or expired password reset token.',
      );
    }

    if (resetTokenRecord.expiresAt <= new Date()) {
      throw new UnauthorizedException(
        'Invalid or expired password reset token.',
      );
    }

    if (!resetTokenRecord.user) {
      throw new UnauthorizedException(
        'Invalid or expired password reset token.',
      );
    }

    const policyResult = this.passwordService.validatePolicy(dto.newPassword);
    if (!policyResult.isValid) {
      throw new BadRequestException(policyResult.errors.join(' '));
    }

    const newPasswordHash = await this.passwordService.hash(dto.newPassword);

    await this.prisma.$transaction(async (tx) => {
      // 1. Update user's passwordHash
      await tx.user.update({
        where: { id: resetTokenRecord.userId },
        data: { passwordHash: newPasswordHash },
      });

      // 2. Mark reset token as used with concurrency protection (must be currently unused)
      const tokenUpdateResult = await tx.passwordResetToken.updateMany({
        where: {
          id: resetTokenRecord.id,
          usedAt: null,
        },
        data: {
          usedAt: new Date(),
        },
      });

      if (tokenUpdateResult.count !== 1) {
        throw new UnauthorizedException(
          'Invalid or expired password reset token.',
        );
      }

      // 3. Revoke all active refresh sessions for the user
      await tx.refreshToken.updateMany({
        where: {
          userId: resetTokenRecord.userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
    });

    await this.safeAudit(AuditEventType.PASSWORD_RESET, {
      userId: resetTokenRecord.userId,
      email: resetTokenRecord.user.email,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return { message: 'Password reset successfully.' };
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
