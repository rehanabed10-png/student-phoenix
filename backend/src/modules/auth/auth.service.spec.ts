import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { RoleName } from '@prisma/client';
import { AuthService } from './auth.service.js';
import type { PrismaService } from '../../common/prisma/prisma.service.js';
import type { UsersService, UserWithRole } from '../users/users.service.js';
import type { PasswordService } from './password.service.js';
import type { TokenService } from './token.service.js';

describe('AuthService', () => {
  let authService: AuthService;
  let mockPrisma: any;
  let mockUsersService: any;
  let mockPasswordService: any;
  let mockTokenService: any;

  const mockUser: UserWithRole = {
    id: 'user-uuid-1',
    email: 'student@phoenix.edu',
    passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$somehash',
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

  const sanitizedUser = {
    id: 'user-uuid-1',
    email: 'student@phoenix.edu',
    firstName: 'John',
    lastName: 'Phoenix',
    role: RoleName.STUDENT,
  };

  const mockExpiresAt = new Date('2026-10-01T00:00:00Z');

  beforeEach(() => {
    mockPrisma = {
      user: {
        update: vi.fn().mockResolvedValue(mockUser),
      },
      refreshToken: {
        create: vi.fn().mockResolvedValue({ id: 'token-uuid-1' }),
        findUnique: vi.fn(),
        update: vi.fn().mockResolvedValue({ id: 'token-uuid-1' }),
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      },
      $transaction: vi
        .fn()
        .mockImplementation((callback) => callback(mockPrisma)),
    };

    mockUsersService = {
      createStudentUser: vi.fn().mockResolvedValue(mockUser),
      findByEmail: vi.fn().mockResolvedValue(mockUser),
      findById: vi.fn().mockResolvedValue(mockUser),
      sanitizeUser: vi.fn().mockReturnValue(sanitizedUser),
    };

    mockPasswordService = {
      validatePolicy: vi.fn().mockReturnValue({ isValid: true, errors: [] }),
      hash: vi.fn().mockResolvedValue('$argon2id$hashedpassword'),
      verify: vi.fn().mockResolvedValue(true),
    };

    mockTokenService = {
      generateAccessToken: vi.fn().mockReturnValue('mock-jwt-access-token'),
      generateRefreshToken: vi
        .fn()
        .mockReturnValue('raw-refresh-token-64chars'),
      hashRefreshToken: vi
        .fn()
        .mockImplementation((token: string) => {
          if (token === 'raw-refresh-token-64chars') {
            return 'sha256-hashed-refresh-token';
          }
          return `hashed-${token}`;
        }),
      getRefreshTokenExpiresIn: vi.fn().mockReturnValue('7d'),
      getRefreshTokenExpiresInMs: vi
        .fn()
        .mockReturnValue(7 * 24 * 60 * 60 * 1000),
      getRefreshTokenExpiresAt: vi.fn().mockReturnValue(mockExpiresAt),
    };

    authService = new AuthService(
      mockPrisma as unknown as PrismaService,
      mockUsersService as unknown as UsersService,
      mockPasswordService as unknown as PasswordService,
      mockTokenService as unknown as TokenService,
    );
  });

  describe('Registration', () => {
    const registerDto = {
      email: 'student@phoenix.edu',
      password: 'StrongPassword123!',
      firstName: 'John',
      lastName: 'Phoenix',
    };

    it('creates STUDENT user via UsersService', async () => {
      const result = await authService.register(registerDto);

      expect(mockUsersService.createStudentUser).toHaveBeenCalledWith({
        email: 'student@phoenix.edu',
        passwordHash: '$argon2id$hashedpassword',
        firstName: 'John',
        lastName: 'Phoenix',
      });
      expect(result.authResponse.user.role).toBe(RoleName.STUDENT);
    });

    it('hashes password with PasswordService', async () => {
      await authService.register(registerDto);

      expect(mockPasswordService.hash).toHaveBeenCalledWith(
        'StrongPassword123!',
      );
    });

    it('rejects invalid password failing password policy', async () => {
      mockPasswordService.validatePolicy.mockReturnValue({
        isValid: false,
        errors: ['Password must be at least 8 characters long.'],
      });

      await expect(
        authService.register({ ...registerDto, password: 'short' }),
      ).rejects.toThrow(BadRequestException);

      expect(mockPasswordService.hash).not.toHaveBeenCalled();
      expect(mockUsersService.createStudentUser).not.toHaveBeenCalled();
    });

    it('rejects duplicate email by propagating ConflictException', async () => {
      mockUsersService.createStudentUser.mockRejectedValue(
        new ConflictException('A user with this email already exists.'),
      );

      await expect(authService.register(registerDto)).rejects.toThrow(
        ConflictException,
      );
    });

    it('never exposes passwordHash in the registration response', async () => {
      const result = await authService.register(registerDto);

      expect((result.authResponse as any).passwordHash).toBeUndefined();
      expect((result.authResponse.user as any).passwordHash).toBeUndefined();
      expect(result.authResponse).toEqual({
        accessToken: 'mock-jwt-access-token',
        user: sanitizedUser,
      });
    });
  });

  describe('Login', () => {
    const loginDto = {
      email: 'student@phoenix.edu',
      password: 'StrongPassword123!',
    };

    it('successful login returns accessToken and sanitized user', async () => {
      const result = await authService.login(loginDto);

      expect(result.authResponse.accessToken).toBe('mock-jwt-access-token');
      expect(result.authResponse.user).toEqual(sanitizedUser);
      expect((result.authResponse.user as any).passwordHash).toBeUndefined();
    });

    it('invalid email throws generic UnauthorizedException', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);

      await expect(authService.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(authService.login(loginDto)).rejects.toThrow(
        'Invalid email or password.',
      );
    });

    it('invalid password throws generic UnauthorizedException', async () => {
      mockPasswordService.verify.mockResolvedValue(false);

      await expect(authService.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(authService.login(loginDto)).rejects.toThrow(
        'Invalid email or password.',
      );
    });

    it('access token generated with correct claims', async () => {
      await authService.login(loginDto);

      expect(mockTokenService.generateAccessToken).toHaveBeenCalledWith({
        sub: 'user-uuid-1',
        email: 'student@phoenix.edu',
        role: RoleName.STUDENT,
      });
    });

    it('refresh token generated on login', async () => {
      await authService.login(loginDto);

      expect(mockTokenService.generateRefreshToken).toHaveBeenCalled();
    });

    it('only refresh-token hash persisted to database using TokenService calculated expiration', async () => {
      await authService.login(loginDto);

      expect(mockTokenService.getRefreshTokenExpiresAt).toHaveBeenCalled();
      expect(mockPrisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          tokenHash: 'sha256-hashed-refresh-token',
          userId: 'user-uuid-1',
          expiresAt: mockExpiresAt,
        },
      });
    });

    it('dynamic/configured expiration is respected from TokenService without hardcoded 7d', async () => {
      const customExpiry = new Date('2026-12-31T23:59:59Z');
      mockTokenService.getRefreshTokenExpiresAt.mockReturnValue(customExpiry);

      await authService.login(loginDto);

      expect(mockPrisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          tokenHash: 'sha256-hashed-refresh-token',
          userId: 'user-uuid-1',
          expiresAt: customExpiry,
        },
      });
    });

    it('raw refresh token never persisted in database', async () => {
      await authService.login(loginDto);

      const createCall = mockPrisma.refreshToken.create.mock.calls[0][0];
      expect(createCall.data.tokenHash).not.toBe('raw-refresh-token-64chars');
      expect(JSON.stringify(createCall.data)).not.toContain(
        'raw-refresh-token-64chars',
      );
    });
  });

  describe('Refresh Token Rotation', () => {
    const rawToken = 'valid-active-refresh-token';
    const activeTokenRecord = {
      id: 'old-token-uuid-1',
      tokenHash: 'hashed-valid-active-refresh-token',
      userId: 'user-uuid-1',
      user: mockUser,
      expiresAt: new Date(Date.now() + 1000000),
      revokedAt: null,
      replacedByTokenId: null,
    };

    it('valid cookie refreshes successfully with atomic rotation', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue(activeTokenRecord);
      mockPrisma.refreshToken.create.mockResolvedValue({
        id: 'new-token-uuid-2',
      });
      mockTokenService.generateRefreshToken.mockReturnValue(
        'new-raw-refresh-token',
      );

      const result = await authService.refresh(rawToken);

      // Verify access token generated
      expect(mockTokenService.generateAccessToken).toHaveBeenCalledWith({
        sub: 'user-uuid-1',
        email: 'student@phoenix.edu',
        role: RoleName.STUDENT,
      });

      // Verify transaction executed
      expect(mockPrisma.$transaction).toHaveBeenCalled();

      // Verify replacement token created
      expect(mockPrisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          tokenHash: 'hashed-new-raw-refresh-token',
          userId: 'user-uuid-1',
          expiresAt: mockExpiresAt,
        },
      });

      // Verify old token revoked conditionally and linked to replacement
      expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          id: 'old-token-uuid-1',
          revokedAt: null,
        },
        data: {
          revokedAt: expect.any(Date),
          replacedByTokenId: 'new-token-uuid-2',
        },
      });

      // Verify response contains accessToken + sanitized user
      expect(result.authResponse).toEqual({
        accessToken: 'mock-jwt-access-token',
        user: sanitizedUser,
      });
      expect(result.rawRefreshToken).toBe('new-raw-refresh-token');
    });

    it('concurrent refresh race: fails rotation and rolls back transaction if old token was revoked concurrently (updateMany count === 0)', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue(activeTokenRecord);
      mockPrisma.refreshToken.create.mockResolvedValue({
        id: 'new-token-uuid-concurrent',
      });
      // Simulate race: another concurrent transaction committed first, so conditional update affects 0 rows
      mockPrisma.refreshToken.updateMany.mockResolvedValue({ count: 0 });

      await expect(authService.refresh(rawToken)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(authService.refresh(rawToken)).rejects.toThrow(
        'Invalid or expired refresh token.',
      );

      // Verify conditional check was performed with revokedAt: null
      expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          id: 'old-token-uuid-1',
          revokedAt: null,
        },
        data: {
          revokedAt: expect.any(Date),
          replacedByTokenId: 'new-token-uuid-concurrent',
        },
      });
    });

    it('rejects missing or empty token', async () => {
      await expect(authService.refresh('')).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(authService.refresh(undefined as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('rejects unknown token hash not found in database', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue(null);

      await expect(authService.refresh('unknown-token')).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(authService.refresh('unknown-token')).rejects.toThrow(
        'Invalid or expired refresh token.',
      );
    });

    it('rejects expired refresh token', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue({
        ...activeTokenRecord,
        expiresAt: new Date(Date.now() - 5000), // Expired in the past
      });

      await expect(authService.refresh(rawToken)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockPrisma.refreshToken.create).not.toHaveBeenCalled();
    });

    it('rejects revoked token without replacement (e.g. after logout)', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue({
        ...activeTokenRecord,
        revokedAt: new Date(),
        replacedByTokenId: null,
      });

      await expect(authService.refresh(rawToken)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockPrisma.refreshToken.create).not.toHaveBeenCalled();
    });

    it('rejects when user no longer exists', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue({
        ...activeTokenRecord,
        user: null,
      });

      await expect(authService.refresh(rawToken)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('Token Reuse Detection', () => {
    it('detects rotated token reuse, revokes descendant chain, and rejects without issuing credentials', async () => {
      // Token A was revoked and replaced by Token B
      const tokenA = {
        id: 'token-a-uuid',
        tokenHash: 'hashed-token-a',
        userId: 'user-uuid-1',
        user: mockUser,
        expiresAt: new Date(Date.now() + 100000),
        revokedAt: new Date('2026-09-01'),
        replacedByTokenId: 'token-b-uuid',
      };

      // Token B was revoked and replaced by Token C
      const tokenB = {
        id: 'token-b-uuid',
        tokenHash: 'hashed-token-b',
        userId: 'user-uuid-1',
        expiresAt: new Date(Date.now() + 100000),
        revokedAt: new Date('2026-09-02'),
        replacedByTokenId: 'token-c-uuid',
      };

      // Token C is currently active
      const tokenC = {
        id: 'token-c-uuid',
        tokenHash: 'hashed-token-c',
        userId: 'user-uuid-1',
        expiresAt: new Date(Date.now() + 100000),
        revokedAt: null,
        replacedByTokenId: null,
      };

      // Setup findUnique mock for traversal
      mockPrisma.refreshToken.findUnique.mockImplementation(
        async ({ where }: any) => {
          if (where.tokenHash === 'hashed-token-a') return tokenA;
          if (where.id === 'token-b-uuid') return tokenB;
          if (where.id === 'token-c-uuid') return tokenC;
          return null;
        },
      );

      // Present reused Token A
      await expect(authService.refresh('token-a')).rejects.toThrow(
        UnauthorizedException,
      );

      // Verify Token C (the active descendant) was revoked
      expect(mockPrisma.refreshToken.update).toHaveBeenCalledWith({
        where: { id: 'token-c-uuid' },
        data: { revokedAt: expect.any(Date) },
      });

      // Verify no new credentials were generated or stored
      expect(mockPrisma.refreshToken.create).not.toHaveBeenCalled();
      expect(mockTokenService.generateAccessToken).not.toHaveBeenCalled();
    });
  });

  describe('Logout', () => {
    it('active token is revoked upon logout', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue({
        id: 'active-token-id',
        tokenHash: 'hashed-active-token',
        revokedAt: null,
      });

      await authService.logout('active-token');

      expect(mockPrisma.refreshToken.update).toHaveBeenCalledWith({
        where: { id: 'active-token-id' },
        data: { revokedAt: expect.any(Date) },
      });
    });

    it('logout succeeds idempotently with missing/undefined cookie', async () => {
      await expect(authService.logout(undefined)).resolves.not.toThrow();
      await expect(authService.logout('')).resolves.not.toThrow();
      expect(mockPrisma.refreshToken.findUnique).not.toHaveBeenCalled();
      expect(mockPrisma.refreshToken.update).not.toHaveBeenCalled();
    });

    it('logout succeeds idempotently with unknown token', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue(null);

      await expect(authService.logout('unknown-token')).resolves.not.toThrow();
      expect(mockPrisma.refreshToken.update).not.toHaveBeenCalled();
    });

    it('logout succeeds idempotently if token was already revoked', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue({
        id: 'already-revoked-id',
        tokenHash: 'hashed-revoked-token',
        revokedAt: new Date(),
      });

      await expect(
        authService.logout('already-revoked-token'),
      ).resolves.not.toThrow();
      expect(mockPrisma.refreshToken.update).not.toHaveBeenCalled();
    });
  });

  describe('Cookie Management', () => {
    it('sets cookie with raw refresh token and secure options using TokenService lifetime', () => {
      const mockRes: any = {
        cookie: vi.fn(),
      };

      authService.setRefreshTokenCookie(mockRes, 'raw-token-abc');

      expect(mockTokenService.getRefreshTokenExpiresInMs).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'phoenix_refresh_token',
        'raw-token-abc',
        expect.objectContaining({
          httpOnly: true,
          sameSite: 'strict',
          path: '/api/auth',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        }),
      );
    });

    it('clears refresh token cookie with matching security parameters', () => {
      const mockRes: any = {
        clearCookie: vi.fn(),
      };

      authService.clearRefreshTokenCookie(mockRes);

      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'phoenix_refresh_token',
        expect.objectContaining({
          httpOnly: true,
          sameSite: 'strict',
          path: '/api/auth',
        }),
      );
    });
  });

  describe('changePassword', () => {
    const validDto = {
      currentPassword: 'OldPassword123!',
      newPassword: 'NewSecurePassword456@',
    };

    it('successfully changes password, updates hash, revokes all refresh tokens, and returns success message', async () => {
      const result = await authService.changePassword('user-uuid-1', validDto);

      expect(mockUsersService.findById).toHaveBeenCalledWith('user-uuid-1');
      expect(mockPasswordService.verify).toHaveBeenCalledWith(
        'OldPassword123!',
        mockUser.passwordHash,
      );
      expect(mockPasswordService.validatePolicy).toHaveBeenCalledWith(
        'NewSecurePassword456@',
      );
      expect(mockPasswordService.hash).toHaveBeenCalledWith(
        'NewSecurePassword456@',
      );
      expect(mockPrisma.$transaction).toHaveBeenCalled();
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'user-uuid-1' },
        data: { passwordHash: '$argon2id$hashedpassword' },
      });
      expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          userId: 'user-uuid-1',
          revokedAt: null,
        },
        data: {
          revokedAt: expect.any(Date),
        },
      });
      expect(result).toEqual({ message: 'Password changed successfully.' });
      // Verify no sensitive tokens or hashes are returned
      expect(result).not.toHaveProperty('password');
      expect(result).not.toHaveProperty('passwordHash');
      expect(result).not.toHaveProperty('accessToken');
      expect(result).not.toHaveProperty('refreshToken');
    });

    it('throws UnauthorizedException if user is not found', async () => {
      mockUsersService.findById.mockResolvedValue(null);

      await expect(
        authService.changePassword('non-existent-user', validDto),
      ).rejects.toThrow(UnauthorizedException);

      expect(mockPasswordService.verify).not.toHaveBeenCalled();
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException if current password verification fails', async () => {
      mockPasswordService.verify.mockResolvedValue(false);

      await expect(
        authService.changePassword('user-uuid-1', validDto),
      ).rejects.toThrow(new UnauthorizedException('Current password is incorrect.'));

      expect(mockPasswordService.validatePolicy).not.toHaveBeenCalled();
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });

    it('throws BadRequestException if new password violates policy', async () => {
      mockPasswordService.validatePolicy.mockReturnValue({
        isValid: false,
        errors: ['Password must be at least 8 characters long.'],
      });

      await expect(
        authService.changePassword('user-uuid-1', {
          currentPassword: 'OldPassword123!',
          newPassword: 'short',
        }),
      ).rejects.toThrow(BadRequestException);

      expect(mockPasswordService.hash).not.toHaveBeenCalled();
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });

    it('throws BadRequestException if new password is identical to current password', async () => {
      await expect(
        authService.changePassword('user-uuid-1', {
          currentPassword: 'SamePassword123!',
          newPassword: 'SamePassword123!',
        }),
      ).rejects.toThrow(
        new BadRequestException('New password cannot be the same as the current password.'),
      );

      expect(mockPasswordService.hash).not.toHaveBeenCalled();
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });

    it('ensures user update and refresh token revocation execute inside a transaction and roll back on error', async () => {
      mockPrisma.refreshToken.updateMany.mockRejectedValue(
        new Error('Database write failure'),
      );

      await expect(
        authService.changePassword('user-uuid-1', validDto),
      ).rejects.toThrow('Database write failure');

      expect(mockPrisma.$transaction).toHaveBeenCalled();
    });

    it('ensures only passwordHash is updated and other user fields cannot be modified', async () => {
      await authService.changePassword('user-uuid-1', validDto);

      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'user-uuid-1' },
        data: { passwordHash: '$argon2id$hashedpassword' },
      });
      const updateData = mockPrisma.user.update.mock.calls[0][0].data;
      expect(Object.keys(updateData)).toEqual(['passwordHash']);
    });
  });
});
