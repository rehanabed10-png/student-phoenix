import { Injectable, OnModuleDestroy } from '@nestjs/common';

/**
 * PrismaService provides the central database client interface for Student Phoenix.
 *
 * NOTE (Phase 1.5 Architecture Lock):
 * This service is prepared for Phase 2 (Authentication & Users), where PostgreSQL
 * models and Prisma migrations will be introduced. It will extend PrismaClient
 * once initial schema models are generated.
 */
@Injectable()
export class PrismaService implements OnModuleDestroy {
  async onModuleDestroy() {
    // Graceful disconnect will be active once models and client are generated in Phase 2
  }
}
