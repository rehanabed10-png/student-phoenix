import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { RoleName } from '@prisma/client';
import { UsersService } from './users.service.js';
import type { PrismaService } from '../../common/prisma/prisma.service.js';

describe('UsersService', () => {
  let usersService: UsersService;
  let mockPrisma: any;

  const mockRole = {
    id: 'role-student-uuid',
    name: RoleName.STUDENT,
    description: 'Student role',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockUserWithRole = {
    id: 'user-uuid-1',
    email: 'student@phoenix.edu',
    passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$somehashvalue',
    firstName: 'John',
    lastName: 'Phoenix',
    roleId: 'role-student-uuid',
    role: mockRole,
    createdAt: new Date('2026-01-01'),
    updatedAt: new Date('2026-01-01'),
  };

  beforeEach(() => {
    mockPrisma = {
      user: {
        findUnique: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
      },
      role: {
        findUnique: vi.fn(),
      },
    };

    usersService = new UsersService(mockPrisma as unknown as PrismaService);
  });

  describe('findByEmail', () => {
    it('1. findByEmail returns user with role', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUserWithRole);

      const result = await usersService.findByEmail('  STUDENT@phoenix.edu  ');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'student@phoenix.edu' },
        include: { role: true },
      });
      expect(result).toEqual(mockUserWithRole);
      expect(result?.role.name).toBe(RoleName.STUDENT);
    });
  });

  describe('findById', () => {
    it('2. findById returns user with role', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUserWithRole);

      const result = await usersService.findById('user-uuid-1');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-uuid-1' },
        include: { role: true },
      });
      expect(result).toEqual(mockUserWithRole);
      expect(result?.role.name).toBe(RoleName.STUDENT);
    });
  });

  describe('createStudentUser', () => {
    it('3. createStudentUser resolves STUDENT role from database', async () => {
      mockPrisma.role.findUnique.mockResolvedValue(mockRole);
      mockPrisma.user.create.mockResolvedValue(mockUserWithRole);

      const input = {
        email: 'Student@Phoenix.edu ',
        passwordHash: '$argon2id$hashvalue',
        firstName: ' John ',
        lastName: ' Phoenix ',
      };

      const result = await usersService.createStudentUser(input);

      expect(mockPrisma.role.findUnique).toHaveBeenCalledWith({
        where: { name: RoleName.STUDENT },
      });
      expect(mockPrisma.user.create).toHaveBeenCalledWith({
        data: {
          email: 'student@phoenix.edu',
          passwordHash: '$argon2id$hashvalue',
          firstName: 'John',
          lastName: 'Phoenix',
          roleId: 'role-student-uuid',
        },
        include: { role: true },
      });
      expect(result).toEqual(mockUserWithRole);
    });

    it('4. createStudentUser never accepts an arbitrary role', async () => {
      // The method signature does not accept a role, and if STUDENT role is not provisioned, it fails safely
      mockPrisma.role.findUnique.mockResolvedValue(null);

      await expect(
        usersService.createStudentUser({
          email: 'test@phoenix.edu',
          passwordHash: 'hash',
          firstName: 'Test',
          lastName: 'User',
        }),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('updateProfile', () => {
    it('5. updateProfile changes firstName/lastName', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUserWithRole);
      const updatedUser = {
        ...mockUserWithRole,
        firstName: 'Jane',
        lastName: 'Doe',
      };
      mockPrisma.user.update.mockResolvedValue(updatedUser);

      const result = await usersService.updateProfile('user-uuid-1', {
        firstName: ' Jane ',
        lastName: ' Doe ',
      });

      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'user-uuid-1' },
        data: {
          firstName: 'Jane',
          lastName: 'Doe',
        },
        include: { role: true },
      });
      expect(result.firstName).toBe('Jane');
      expect(result.lastName).toBe('Doe');
    });

    it('6. updateProfile cannot modify role', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUserWithRole);
      mockPrisma.user.update.mockResolvedValue(mockUserWithRole);

      // Attempt to pass malicious role properties
      const maliciousDto: any = {
        firstName: 'Jane',
        role: RoleName.ADMIN,
        roleId: 'admin-role-uuid',
      };

      await usersService.updateProfile('user-uuid-1', maliciousDto);

      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'user-uuid-1' },
        data: {
          firstName: 'Jane',
        },
        include: { role: true },
      });
      expect(mockPrisma.user.update.mock.calls[0][0].data).not.toHaveProperty('role');
      expect(mockPrisma.user.update.mock.calls[0][0].data).not.toHaveProperty('roleId');
    });

    it('7. updateProfile cannot modify email', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUserWithRole);
      mockPrisma.user.update.mockResolvedValue(mockUserWithRole);

      // Attempt to pass malicious email property
      const maliciousDto: any = {
        lastName: 'Doe',
        email: 'hacker@malicious.com',
      };

      await usersService.updateProfile('user-uuid-1', maliciousDto);

      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'user-uuid-1' },
        data: {
          lastName: 'Doe',
        },
        include: { role: true },
      });
      expect(mockPrisma.user.update.mock.calls[0][0].data).not.toHaveProperty('email');
    });
  });

  describe('sanitizeUser', () => {
    it('8. sanitizeUser excludes passwordHash', () => {
      const sanitized = usersService.sanitizeUser(mockUserWithRole);

      expect((sanitized as any).passwordHash).toBeUndefined();
      expect(Object.keys(sanitized)).not.toContain('passwordHash');
      expect((sanitized as any).roleId).toBeUndefined();
      expect((sanitized as any).createdAt).toBeUndefined();
      expect((sanitized as any).updatedAt).toBeUndefined();
    });

    it('9. sanitizeUser includes id/email/name/role', () => {
      const sanitized = usersService.sanitizeUser(mockUserWithRole);

      expect(sanitized).toEqual({
        id: 'user-uuid-1',
        email: 'student@phoenix.edu',
        firstName: 'John',
        lastName: 'Phoenix',
        role: RoleName.STUDENT,
      });
    });
  });

  describe('Error handling', () => {
    it('10. Database errors are propagated/handled appropriately without leaking sensitive information', async () => {
      mockPrisma.role.findUnique.mockResolvedValue(mockRole);
      // Simulate unique constraint collision from Prisma
      mockPrisma.user.create.mockRejectedValue({ code: 'P2002' });

      await expect(
        usersService.createStudentUser({
          email: 'duplicate@phoenix.edu',
          passwordHash: 'hash',
          firstName: 'John',
          lastName: 'Doe',
        }),
      ).rejects.toThrow(ConflictException);

      // Non-existent user on update throws NotFoundException
      mockPrisma.user.findUnique.mockResolvedValue(null);
      await expect(
        usersService.updateProfile('non-existent-id', { firstName: 'New' }),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
