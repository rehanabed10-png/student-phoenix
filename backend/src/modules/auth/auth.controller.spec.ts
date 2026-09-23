import { describe, it, expect, beforeEach, vi } from 'vitest';
import { UnauthorizedException } from '@nestjs/common';
import { RoleName } from '@prisma/client';
import { AuthController } from './auth.controller.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import type { AuthService } from './auth.service.js';

describe('AuthController', () => {
  let controller: AuthController;
  let mockAuthService: any;

  const mockAuthResponse = {
    accessToken: 'mock-access-token',
    user: {
      id: 'user-uuid-1',
      email: 'student@phoenix.edu',
      firstName: 'John',
      lastName: 'Phoenix',
      role: RoleName.STUDENT,
    },
  };

  beforeEach(() => {
    mockAuthService = {
      register: vi.fn().mockResolvedValue({
        authResponse: mockAuthResponse,
        rawRefreshToken: 'raw-refresh-token',
      }),
      login: vi.fn().mockResolvedValue({
        authResponse: mockAuthResponse,
        rawRefreshToken: 'raw-refresh-token',
      }),
      refresh: vi.fn().mockResolvedValue({
        authResponse: mockAuthResponse,
        rawRefreshToken: 'new-rotated-refresh-token',
      }),
      logout: vi.fn().mockResolvedValue(undefined),
      changePassword: vi
        .fn()
        .mockResolvedValue({ message: 'Password changed successfully.' }),
      requestPasswordReset: vi.fn().mockResolvedValue({
        message:
          'If an account exists for this email, a password reset link has been requested.',
      }),
      resetPassword: vi
        .fn()
        .mockResolvedValue({ message: 'Password reset successfully.' }),
      setRefreshTokenCookie: vi.fn(),
      clearRefreshTokenCookie: vi.fn(),
    };

    controller = new AuthController(mockAuthService as unknown as AuthService);
  });

  describe('register', () => {
    it('register route invokes AuthService.register with request context, sets cookie, and returns authResponse', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
      };
      const mockRes: any = {};
      const dto = {
        email: 'student@phoenix.edu',
        password: 'StrongPassword123!',
        firstName: 'John',
        lastName: 'Phoenix',
      };

      const result = await controller.register(dto, mockReq, mockRes);

      expect(mockAuthService.register).toHaveBeenCalledWith(dto, {
        ipAddress: '127.0.0.1',
        userAgent: 'VitestClient',
      });
      expect(mockAuthService.setRefreshTokenCookie).toHaveBeenCalledWith(
        mockRes,
        'raw-refresh-token',
      );
      expect(result).toEqual(mockAuthResponse);
    });
  });

  describe('login', () => {
    it('login route invokes AuthService.login with request context, sets cookie, and returns authResponse', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
      };
      const mockRes: any = {};
      const dto = {
        email: 'student@phoenix.edu',
        password: 'StrongPassword123!',
      };

      const result = await controller.login(dto, mockReq, mockRes);

      expect(mockAuthService.login).toHaveBeenCalledWith(dto, {
        ipAddress: '127.0.0.1',
        userAgent: 'VitestClient',
      });
      expect(mockAuthService.setRefreshTokenCookie).toHaveBeenCalledWith(
        mockRes,
        'raw-refresh-token',
      );
      expect(result).toEqual(mockAuthResponse);
    });
  });

  describe('refresh', () => {
    it('reads cookie, rotates token, sets replacement cookie, and returns authResponse', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
        cookies: {
          phoenix_refresh_token: 'existing-cookie-token',
        },
      };
      const mockRes: any = {};

      const result = await controller.refresh(mockReq, mockRes);

      expect(mockAuthService.refresh).toHaveBeenCalledWith(
        'existing-cookie-token',
        {
          ipAddress: '127.0.0.1',
          userAgent: 'VitestClient',
        },
      );
      expect(mockAuthService.setRefreshTokenCookie).toHaveBeenCalledWith(
        mockRes,
        'new-rotated-refresh-token',
      );
      expect(result).toEqual(mockAuthResponse);
    });

    it('rejects and clears cookie if refresh cookie is missing', async () => {
      const mockReq: any = {
        cookies: {},
      };
      const mockRes: any = {};

      await expect(controller.refresh(mockReq, mockRes)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockAuthService.clearRefreshTokenCookie).toHaveBeenCalledWith(
        mockRes,
      );
      expect(mockAuthService.refresh).not.toHaveBeenCalled();
    });

    it('clears cookie and propagates error if AuthService.refresh fails', async () => {
      const mockReq: any = {
        cookies: {
          phoenix_refresh_token: 'invalid-or-reused-token',
        },
      };
      const mockRes: any = {};
      mockAuthService.refresh.mockRejectedValue(
        new UnauthorizedException('Invalid or expired refresh token.'),
      );

      await expect(controller.refresh(mockReq, mockRes)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockAuthService.clearRefreshTokenCookie).toHaveBeenCalledWith(
        mockRes,
      );
    });
  });

  describe('logout', () => {
    it('calls AuthService.logout with context, clears cookie, and returns success message', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
        cookies: {
          phoenix_refresh_token: 'session-cookie-token',
        },
      };
      const mockRes: any = {};

      const result = await controller.logout(mockReq, mockRes);

      expect(mockAuthService.logout).toHaveBeenCalledWith(
        'session-cookie-token',
        {
          ipAddress: '127.0.0.1',
          userAgent: 'VitestClient',
        },
      );
      expect(mockAuthService.clearRefreshTokenCookie).toHaveBeenCalledWith(
        mockRes,
      );
      expect(result).toEqual({ message: 'Logged out successfully.' });
    });
  });

  describe('changePassword', () => {
    it('requires JwtAuthGuard metadata on the route', () => {
      const guards = Reflect.getMetadata(
        '__guards__',
        controller.changePassword,
      );
      expect(guards).toBeDefined();
      expect(guards).toContain(JwtAuthGuard);
    });

    it('delegates request.user.id and body dto to AuthService.changePassword and returns message', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
        user: {
          id: 'user-uuid-1',
          email: 'student@phoenix.edu',
          role: RoleName.STUDENT,
        },
      };
      const dto = {
        currentPassword: 'OldPassword123!',
        newPassword: 'NewSecurePassword456@',
      };

      const result = await controller.changePassword(mockReq, dto);

      expect(mockAuthService.changePassword).toHaveBeenCalledWith(
        'user-uuid-1',
        dto,
        {
          ipAddress: '127.0.0.1',
          userAgent: 'VitestClient',
        },
      );
      expect(result).toEqual({ message: 'Password changed successfully.' });
    });
  });

  describe('forgotPassword', () => {
    it('does NOT have JwtAuthGuard metadata (public endpoint)', () => {
      const guards = Reflect.getMetadata(
        '__guards__',
        controller.forgotPassword,
      );
      expect(guards).toBeUndefined();
    });

    it('delegates dto to AuthService.requestPasswordReset with context and returns generic response', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
      };
      const dto = { email: 'student@phoenix.edu' };
      const result = await controller.forgotPassword(dto, mockReq);

      expect(mockAuthService.requestPasswordReset).toHaveBeenCalledWith(
        dto,
        {
          ipAddress: '127.0.0.1',
          userAgent: 'VitestClient',
        },
      );
      expect(result).toEqual({
        message:
          'If an account exists for this email, a password reset link has been requested.',
      });
    });
  });

  describe('resetPassword', () => {
    it('does NOT have JwtAuthGuard metadata (public endpoint)', () => {
      const guards = Reflect.getMetadata(
        '__guards__',
        controller.resetPassword,
      );
      expect(guards).toBeUndefined();
    });

    it('delegates dto to AuthService.resetPassword with context and returns success message', async () => {
      const mockReq: any = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'VitestClient' },
      };
      const dto = {
        token: 'raw-reset-token-64chars',
        newPassword: 'BrandNewSecurePassword123!',
      };
      const result = await controller.resetPassword(dto, mockReq);

      expect(mockAuthService.resetPassword).toHaveBeenCalledWith(
        dto,
        {
          ipAddress: '127.0.0.1',
          userAgent: 'VitestClient',
        },
      );
      expect(result).toEqual({ message: 'Password reset successfully.' });
    });
  });
});
