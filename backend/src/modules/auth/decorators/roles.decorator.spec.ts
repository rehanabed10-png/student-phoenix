import { describe, it, expect } from 'vitest';
import { Reflector } from '@nestjs/core';
import { RoleName } from '@prisma/client';
import { Roles, ROLES_KEY } from './roles.decorator.js';

describe('Roles Decorator', () => {
  const reflector = new Reflector();

  it('metadata is correctly assigned with a single role', () => {
    class TestController {
      @Roles(RoleName.ADMIN)
      testEndpoint() {}
    }

    const roles = reflector.get<RoleName[]>(
      ROLES_KEY,
      TestController.prototype.testEndpoint,
    );

    expect(roles).toEqual([RoleName.ADMIN]);
  });

  it('metadata is correctly assigned with multiple roles', () => {
    class TestController {
      @Roles(RoleName.FACULTY, RoleName.ADMIN)
      testEndpoint() {}
    }

    const roles = reflector.get<RoleName[]>(
      ROLES_KEY,
      TestController.prototype.testEndpoint,
    );

    expect(roles).toEqual([RoleName.FACULTY, RoleName.ADMIN]);
  });
});
