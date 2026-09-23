import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { ForgotPasswordDto } from './dto/forgot-password.dto.js';
import { ResetPasswordDto } from './dto/reset-password.dto.js';
import { AuthResponseDto } from './dto/auth-response.dto.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import type { AuthenticatedUser } from './types/authenticated-user.js';
import { REFRESH_TOKEN_COOKIE_NAME } from './utils/cookies.util.js';

interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}

function extractRequestContext(req: Request) {
  return {
    ipAddress: req.ip,
    userAgent: req.headers ? req.headers['user-agent'] : undefined,
  };
}

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * POST /api/auth/register
   * Registers a new student account and sets the refresh token cookie.
   */
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const { authResponse, rawRefreshToken } =
      await this.authService.register(dto, extractRequestContext(req));
    this.authService.setRefreshTokenCookie(res, rawRefreshToken);
    return authResponse;
  }

  /**
   * POST /api/auth/login
   * Authenticates a user and sets the refresh token cookie.
   * Throttled to 15 attempts per minute to mitigate brute-force attacks.
   */
  @Post('login')
  @Throttle({ default: { limit: 15, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const { authResponse, rawRefreshToken } =
      await this.authService.login(dto, extractRequestContext(req));
    this.authService.setRefreshTokenCookie(res, rawRefreshToken);
    return authResponse;
  }

  /**
   * POST /api/auth/refresh
   * Rotates the refresh token and issues a new access token.
   * Refresh token is read strictly from the phoenix_refresh_token HttpOnly cookie.
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const rawRefreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME];
    if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
      this.authService.clearRefreshTokenCookie(res);
      throw new UnauthorizedException('Refresh token is required.');
    }

    try {
      const { authResponse, rawRefreshToken: newRefreshToken } =
        await this.authService.refresh(
          rawRefreshToken,
          extractRequestContext(req),
        );
      this.authService.setRefreshTokenCookie(res, newRefreshToken);
      return authResponse;
    } catch (error) {
      this.authService.clearRefreshTokenCookie(res);
      throw error;
    }
  }

  /**
   * POST /api/auth/logout
   * Revokes the refresh token session and clears the HttpOnly cookie.
   * Safe and idempotent.
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    const rawRefreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME];
    await this.authService.logout(
      rawRefreshToken,
      extractRequestContext(req),
    );
    this.authService.clearRefreshTokenCookie(res);
    return { message: 'Logged out successfully.' };
  }

  /**
   * POST /api/auth/change-password
   * Authenticated password change for current user.
   * Requires a valid access JWT via JwtAuthGuard.
   * Invalidates all active refresh sessions for this user.
   */
  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @Req() req: AuthenticatedRequest,
    @Body() dto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.changePassword(
      req.user.id,
      dto,
      extractRequestContext(req),
    );
  }

  /**
   * POST /api/auth/forgot-password
   * Requests a password reset link for the provided email address.
   * Public endpoint. Defends against account enumeration with generic response.
   * Throttled to 15 attempts per minute to prevent reset-request abuse.
   */
  @Post('forgot-password')
  @Throttle({ default: { limit: 15, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
    @Req() req: Request,
  ): Promise<{ message: string }> {
    return this.authService.requestPasswordReset(
      dto,
      extractRequestContext(req),
    );
  }

  /**
   * POST /api/auth/reset-password
   * Resets the user's password using a verified reset token.
   * Public endpoint. The reset token is the credential.
   * Throttled to 15 attempts per minute to mitigate automated token guessing.
   */
  @Post('reset-password')
  @Throttle({ default: { limit: 15, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body() dto: ResetPasswordDto,
    @Req() req: Request,
  ): Promise<{ message: string }> {
    return this.authService.resetPassword(
      dto,
      extractRequestContext(req),
    );
  }
}

