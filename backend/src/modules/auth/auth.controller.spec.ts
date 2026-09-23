import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RoleName } from '@prisma/client';
import { AuthController } from './auth.controller.js';
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
      setRefreshTokenCookie: vi.fn(),
    };

    controller = new AuthController(mockAuthService as unknown as AuthService);
  });

  it('register route invokes AuthService.register, sets cookie, and returns authResponse', async () => {
    const mockRes: any = {};
    const dto = {
      email: 'student@phoenix.edu',
      password: 'StrongPassword123!',
      firstName: 'John',
      lastName: 'Phoenix',
    };

    const result = await controller.register(dto, mockRes);

    expect(mockAuthService.register).toHaveBeenCalledWith(dto);
    expect(mockAuthService.setRefreshTokenCookie).toHaveBeenCalledWith(
      mockRes,
      'raw-refresh-token',
    );
    expect(result).toEqual(mockAuthResponse);
  });

  it('login route invokes AuthService.login, sets cookie, and returns authResponse', async () => {
    const mockRes: any = {};
    const dto = {
      email: 'student@phoenix.edu',
      password: 'StrongPassword123!',
    };

    const result = await controller.login(dto, mockRes);

    expect(mockAuthService.login).toHaveBeenCalledWith(dto);
    expect(mockAuthService.setRefreshTokenCookie).toHaveBeenCalledWith(
      mockRes,
      'raw-refresh-token',
    );
    expect(result).toEqual(mockAuthResponse);
  });
});
