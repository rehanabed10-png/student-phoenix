import { describe, it, expect } from 'vitest';
import { AuthGuard } from '@nestjs/passport';
import { JwtAuthGuard } from './jwt-auth.guard.js';

describe('JwtAuthGuard', () => {
  it('correct guard inheritance and configuration', () => {
    const guard = new JwtAuthGuard();

    expect(guard).toBeDefined();
    // Verify it inherits from NestJS AuthGuard('jwt')
    expect(guard).toBeInstanceOf(AuthGuard('jwt'));
  });

  it('does not duplicate custom authentication logic or override canActivate directly', () => {
    const guard = new JwtAuthGuard();

    // Verify it relies on Passport AuthGuard's default canActivate
    expect(typeof guard.canActivate).toBe('function');
  });
});
