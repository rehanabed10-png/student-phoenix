import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RoleName } from '@prisma/client';
import { RolesGuard } from './roles.guard.js';
import type { AuthenticatedUser } from '../types/authenticated-user.js';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  const createMockContext = (user?: AuthenticatedUser): ExecutionContext => {
    const handler = () => {};
    const controllerClass = class {};

    return {
      getHandler: () => handler,
      getClass: () => controllerClass,
      switchToHttp: () => ({
        getRequest: () => ({ user }),
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  it('allows access when no role metadata exists', () => {
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

    const context = createMockContext({
      id: 'user-1',
      email: 'student@phoenix.edu',
      role: RoleName.STUDENT,
    });

    const result = guard.canActivate(context);
    expect(result).toBe(true);
  });

  it('allows access when empty role metadata exists', () => {
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue([]);

    const context = createMockContext({
      id: 'user-1',
      email: 'student@phoenix.edu',
      role: RoleName.STUDENT,
    });

    const result = guard.canActivate(context);
    expect(result).toBe(true);
  });

  it('allows access for a matching role', () => {
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue([
      RoleName.ADMIN,
      RoleName.FACULTY,
    ]);

    const context = createMockContext({
      id: 'faculty-1',
      email: 'faculty@phoenix.edu',
      role: RoleName.FACULTY,
    });

    const result = guard.canActivate(context);
    expect(result).toBe(true);
  });

  it('rejects a non-matching role with ForbiddenException', () => {
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue([RoleName.ADMIN]);

    const context = createMockContext({
      id: 'student-1',
      email: 'student@phoenix.edu',
      role: RoleName.STUDENT,
    });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(() => guard.canActivate(context)).toThrow(
      'You do not have permission to access this resource.',
    );
  });

  it('handles missing authenticated user appropriately with UnauthorizedException', () => {
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue([RoleName.STUDENT]);

    const context = createMockContext(undefined);

    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
    expect(() => guard.canActivate(context)).toThrow('Authentication required.');
  });
});
