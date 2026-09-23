import { SetMetadata } from '@nestjs/common';
import type { RoleName } from '@prisma/client';

export const ROLES_KEY = 'roles';

/**
 * @Roles decorator attaches required role metadata to route handlers or controllers.
 * Accepts one or more RoleName values from Prisma schema.
 *
 * Example:
 * @Roles(RoleName.ADMIN)
 * @Roles(RoleName.FACULTY, RoleName.ADMIN)
 */
export const Roles = (...roles: RoleName[]) => SetMetadata(ROLES_KEY, roles);
