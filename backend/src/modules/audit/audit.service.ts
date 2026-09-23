import { Injectable } from '@nestjs/common';
import { AuditEventType, type Prisma } from '@prisma/client';
import { PrismaService } from '../../common/prisma/prisma.service.js';

export interface AuditLogData {
  userId?: string;
  email?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Prisma.InputJsonValue;
}

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Records an authentication security audit log event.
   * Persists event details to the database and surfaces any persistence errors to caller.
   */
  async log(
    eventType: AuditEventType,
    data?: AuditLogData,
  ): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        eventType,
        userId: data?.userId ?? null,
        email: data?.email ?? null,
        ipAddress: data?.ipAddress ?? null,
        userAgent: data?.userAgent ?? null,
        metadata: data?.metadata ?? undefined,
      },
    });
  }
}
