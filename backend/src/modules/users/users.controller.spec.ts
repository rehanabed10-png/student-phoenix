import { describe, it, expect, beforeEach, vi } from 'vitest';
import { UnauthorizedException, NotFoundException } from '@nestjs/common';
import { RoleName } from '@prisma/client';
import { UsersController } from './users.controller.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import type { UsersService, UserWithRole } from './users.service.js';
import type { AuthenticatedUser } from '../auth/types/authenticated-user.js';
import type { UserResponseDto } from './dto/user-response.dto.js';

describe('UsersController', () => {
  let controller: UsersController;
  let mockUsersService: any;

  const mockAuthenticatedUser: AuthenticatedUser = {
    id: 'user-uuid-1',
    email: 'student@phoenix.edu',
    role: RoleName.STUDENT,
  };

  const mockDbUser: UserWithRole = {
    id: 'user-uuid-1',
    email: 'student@phoenix.edu',
    passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$secretHashValue',
    firstName: 'John',
    lastName: 'Phoenix',
    roleId: 'role-student-uuid',
    role: {
      id: 'role-student-uuid',
      name: RoleName.STUDENT,
      description: 'Student role',
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const sanitizedUserResponse: UserResponseDto = {
    id: 'user-uuid-1',
    email: 'student@phoenix.edu',
    firstName: 'John',
    lastName: 'Phoenix',
    role: RoleName.STUDENT,
  };

  beforeEach(() => {
    mockUsersService = {
      findById: vi.fn().mockResolvedValue(mockDbUser),
      updateProfile: vi.fn().mockResolvedValue(mockDbUser),
      sanitizeUser: vi.fn().mockReturnValue(sanitizedUserResponse),
    };

    controller = new UsersController(
      mockUsersService as unknown as UsersService,
    );
  });

  describe('Guard Configuration', () => {
    it('UsersController is protected with JwtAuthGuard', () => {
      const guards = Reflect.getMetadata('__guards__', UsersController);
      expect(guards).toBeDefined();
      expect(guards).toContain(JwtAuthGuard);
    });
  });

  describe('GET /api/users/me', () => {
    it('returns sanitized user profile using identity from request.user.id', async () => {
      const mockReq: any = {
        user: mockAuthenticatedUser,
      };

      const result = await controller.getProfile(mockReq);

      expect(mockUsersService.findById).toHaveBeenCalledWith('user-uuid-1');
      expect(mockUsersService.sanitizeUser).toHaveBeenCalledWith(mockDbUser);
      expect(result).toEqual(sanitizedUserResponse);
      expect((result as any).passwordHash).toBeUndefined();
    });

    it('throws UnauthorizedException if authenticated user no longer exists in database', async () => {
      mockUsersService.findById.mockResolvedValue(null);

      const mockReq: any = {
        user: {
          id: 'deleted-user-uuid',
          email: 'ghost@phoenix.edu',
          role: RoleName.STUDENT,
        },
      };

      await expect(controller.getProfile(mockReq)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(controller.getProfile(mockReq)).rejects.toThrow(
        'User not found.',
      );
    });
  });

  describe('PATCH /api/users/me', () => {
    it('updates profile using identity from request.user.id and returns sanitized response', async () => {
      const mockReq: any = {
        user: mockAuthenticatedUser,
      };
      const updateDto = {
        firstName: 'Jane',
        lastName: 'Doe',
      };
      const updatedDbUser = {
        ...mockDbUser,
        firstName: 'Jane',
        lastName: 'Doe',
      };
      const sanitizedUpdatedResponse = {
        ...sanitizedUserResponse,
        firstName: 'Jane',
        lastName: 'Doe',
      };

      mockUsersService.updateProfile.mockResolvedValue(updatedDbUser);
      mockUsersService.sanitizeUser.mockReturnValue(sanitizedUpdatedResponse);

      const result = await controller.updateProfile(mockReq, updateDto);

      expect(mockUsersService.updateProfile).toHaveBeenCalledWith(
        'user-uuid-1',
        updateDto,
      );
      expect(result).toEqual(sanitizedUpdatedResponse);
      expect(result.firstName).toBe('Jane');
      expect(result.lastName).toBe('Doe');
    });

    it('throws UnauthorizedException if user no longer exists during updateProfile', async () => {
      mockUsersService.updateProfile.mockRejectedValue(
        new NotFoundException('User not found.'),
      );

      const mockReq: any = {
        user: {
          id: 'non-existent-user',
          email: 'nobody@phoenix.edu',
          role: RoleName.STUDENT,
        },
      };

      await expect(
        controller.updateProfile(mockReq, { firstName: 'New' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('Security Restrictions', () => {
    it('always uses request.user.id and cannot be overridden by external params', async () => {
      const mockReq: any = {
        user: {
          id: 'actual-jwt-user-id',
          email: 'legit@phoenix.edu',
          role: RoleName.STUDENT,
        },
      };

      // Even if attacker attempted to supply malicious parameters
      const maliciousDto: any = {
        id: 'attacker-chosen-user-id',
        userId: 'attacker-chosen-user-id',
        role: RoleName.ADMIN,
        email: 'hacker@malicious.com',
        firstName: 'Hacked',
      };

      await controller.updateProfile(mockReq, maliciousDto);

      // Must strictly use req.user.id
      expect(mockUsersService.updateProfile).toHaveBeenCalledWith(
        'actual-jwt-user-id',
        maliciousDto,
      );
    });

    it('sanitized response never exposes passwordHash, roleId, or internal session details', async () => {
      const mockReq: any = {
        user: mockAuthenticatedUser,
      };

      const result = await controller.getProfile(mockReq);

      expect((result as any).passwordHash).toBeUndefined();
      expect((result as any).roleId).toBeUndefined();
      expect(Object.keys(result)).toEqual([
        'id',
        'email',
        'firstName',
        'lastName',
        'role',
      ]);
    });
  });
});
