import type { RoleName } from '@prisma/client';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: RoleName;
}
