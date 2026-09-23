import { Body, Controller, HttpCode, HttpStatus, Post, Res } from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { AuthResponseDto } from './dto/auth-response.dto.js';

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
}
