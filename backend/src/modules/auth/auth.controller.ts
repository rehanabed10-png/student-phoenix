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
import type { Request, Response } from 'express';
import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { AuthResponseDto } from './dto/auth-response.dto.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import type { AuthenticatedUser } from './types/authenticated-user.js';
import { REFRESH_TOKEN_COOKIE_NAME } from './utils/cookies.util.js';

interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
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
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const { authResponse, rawRefreshToken } =
      await this.authService.register(dto);
    this.authService.setRefreshTokenCookie(res, rawRefreshToken);
    return authResponse;
  }

  /**
   * POST /api/auth/login
   * Authenticates a user and sets the refresh token cookie.
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const { authResponse, rawRefreshToken } =
      await this.authService.login(dto);
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
        await this.authService.refresh(rawRefreshToken);
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
    await this.authService.logout(rawRefreshToken);
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
    return this.authService.changePassword(req.user.id, dto);
  }
}

