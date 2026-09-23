import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { RoleName } from '@prisma/client';
import type { User, Role } from '@prisma/client';
import { PrismaService } from '../../common/prisma/prisma.service.js';
import { UpdateProfileDto } from './dto/update-profile.dto.js';
import { UserResponseDto } from './dto/user-response.dto.js';

export type UserWithRole = User & { role: Role };

export interface CreateStudentUserData {
  email: string;
  passwordHash: string;
  firstName: string;
  lastName: string;
}

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Finds a user by email, including their Role relation.
   * Internal service method: returned object may contain passwordHash for auth verification.
   */
  async findByEmail(email: string): Promise<UserWithRole | null> {
    return this.prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
      include: { role: true },
    });
  }

  /**
   * Finds a user by unique ID, including their Role relation.
   */
  async findById(id: string): Promise<UserWithRole | null> {
    return this.prisma.user.findUnique({
      where: { id },
      include: { role: true },
    });
  }

  /**
   * Creates a new user with the STUDENT role.
   * Resolves the STUDENT role ID dynamically from the database.
   * Callers cannot pass an arbitrary role.
   */
  async createStudentUser(data: CreateStudentUserData): Promise<UserWithRole> {
    const studentRole = await this.prisma.role.findUnique({
      where: { name: RoleName.STUDENT },
    });

    if (!studentRole) {
      throw new InternalServerErrorException(
        'Default STUDENT role is not provisioned in the database.',
      );
    }

    try {
      return await this.prisma.user.create({
        data: {
          email: data.email.toLowerCase().trim(),
          passwordHash: data.passwordHash,
          firstName: data.firstName.trim(),
          lastName: data.lastName.trim(),
          roleId: studentRole.id,
        },
        include: { role: true },
      });
    } catch (error: any) {
      if (error?.code === 'P2002') {
        throw new ConflictException('A user with this email already exists.');
      }
      throw error;
    }
  }

  /**
   * Updates only profile fields (firstName, lastName).
   * Strictly disallows updating email, passwordHash, role, or id.
   */
  async updateProfile(
    id: string,
    dto: UpdateProfileDto,
  ): Promise<UserWithRole> {
    const existing = await this.findById(id);
    if (!existing) {
      throw new NotFoundException('User not found.');
    }

    const dataToUpdate: { firstName?: string; lastName?: string } = {};

    if (dto.firstName !== undefined) {
      dataToUpdate.firstName = dto.firstName.trim();
    }
    if (dto.lastName !== undefined) {
      dataToUpdate.lastName = dto.lastName.trim();
    }

    return this.prisma.user.update({
      where: { id },
      data: dataToUpdate,
      include: { role: true },
    });
  }

  /**
   * Sanitizes a user object for safe HTTP responses,
   * returning ONLY id, email, firstName, lastName, and role.
   * Excludes passwordHash, refresh tokens, roleId, timestamps,
   * and internal database/session fields.
   */
  sanitizeUser(user: UserWithRole): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role.name,
    };
  }
}
