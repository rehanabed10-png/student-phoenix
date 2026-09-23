import {
  Controller,
  Get,
  Patch,
  Body,
  Req,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from './users.service.js';
import { UpdateProfileDto } from './dto/update-profile.dto.js';
import { UserResponseDto } from './dto/user-response.dto.js';

@Controller('api/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /**
   * GET /api/users/me
   * Retrieves the authenticated user's profile.
   * Authentication guard will be integrated in Phase 2.3 Step 5.
   */
  @Get('me')
  async getProfile(@Req() req: Request): Promise<UserResponseDto> {
    const user = (req as any).user;
    if (!user?.id) {
      throw new UnauthorizedException('Authentication required.');
    }

    const found = await this.usersService.findById(user.id);
    if (!found) {
      throw new NotFoundException('User not found.');
    }

    return this.usersService.sanitizeUser(found);
  }

  /**
   * PATCH /api/users/me
   * Updates profile fields for the authenticated user.
   * Authentication guard will be integrated in Phase 2.3 Step 5.
   */
  @Patch('me')
  async updateProfile(
    @Req() req: Request,
    @Body() dto: UpdateProfileDto,
  ): Promise<UserResponseDto> {
    const user = (req as any).user;
    if (!user?.id) {
      throw new UnauthorizedException('Authentication required.');
    }

    const updated = await this.usersService.updateProfile(user.id, dto);
    return this.usersService.sanitizeUser(updated);
  }
}
