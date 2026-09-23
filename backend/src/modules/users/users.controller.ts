import {
  Controller,
  Get,
  Patch,
  Body,
  Req,
  UseGuards,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from './users.service.js';
import { UpdateProfileDto } from './dto/update-profile.dto.js';
import { UserResponseDto } from './dto/user-response.dto.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import type { AuthenticatedUser } from '../auth/types/authenticated-user.js';

interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}

@Controller('api/users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /**
   * GET /api/users/me
   * Retrieves the authenticated user's sanitized profile.
   * Requires a valid access JWT via JwtAuthGuard.
   */
  @Get('me')
  async getProfile(
    @Req() req: AuthenticatedRequest,
  ): Promise<UserResponseDto> {
    const found = await this.usersService.findById(req.user.id);
    if (!found) {
      throw new UnauthorizedException('User not found.');
    }

    return this.usersService.sanitizeUser(found);
  }

  /**
   * PATCH /api/users/me
   * Updates profile fields for the authenticated user.
   * Requires a valid access JWT via JwtAuthGuard.
   * Only allows modifying firstName and lastName.
   */
  @Patch('me')
  async updateProfile(
    @Req() req: AuthenticatedRequest,
    @Body() dto: UpdateProfileDto,
  ): Promise<UserResponseDto> {
    try {
      const updated = await this.usersService.updateProfile(req.user.id, dto);
      return this.usersService.sanitizeUser(updated);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw new UnauthorizedException('User not found.');
      }
      throw error;
    }
  }
}
