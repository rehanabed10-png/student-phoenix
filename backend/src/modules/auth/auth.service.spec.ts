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

  beforeEach(() => {
    mockPrisma = {
      refreshToken: {
        create: vi.fn().mockResolvedValue({ id: 'token-uuid-1' }),
      },
    };

    mockUsersService = {
      createStudentUser: vi.fn().mockResolvedValue(mockUser),
      findByEmail: vi.fn().mockResolvedValue(mockUser),
      sanitizeUser: vi.fn().mockReturnValue(sanitizedUser),
    };

    mockPasswordService = {
      validatePolicy: vi.fn().mockReturnValue({ isValid: true, errors: [] }),
      hash: vi.fn().mockResolvedValue('$argon2id$hashedpassword'),
      verify: vi.fn().mockResolvedValue(true),
    };

    const mockExpiresAt = new Date('2026-10-01T00:00:00Z');
    mockTokenService = {
      generateAccessToken: vi.fn().mockReturnValue('mock-jwt-access-token'),
      generateRefreshToken: vi.fn().mockReturnValue('raw-refresh-token-64chars'),
      hashRefreshToken: vi.fn().mockReturnValue('sha256-hashed-refresh-token'),
      getRefreshTokenExpiresIn: vi.fn().mockReturnValue('7d'),
      getRefreshTokenExpiresInMs: vi.fn().mockReturnValue(7 * 24 * 60 * 60 * 1000),
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
          expiresAt: new Date('2026-10-01T00:00:00Z'),
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

  describe('setRefreshTokenCookie', () => {
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
  });
});
