import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuditEventType } from '@prisma/client';
import { AuditService } from './audit.service.js';
import type { PrismaService } from '../../common/prisma/prisma.service.js';

describe('AuditService', () => {
  let auditService: AuditService;
  let mockPrisma: any;

  beforeEach(() => {
    mockPrisma = {
      auditLog: {
        create: vi.fn().mockResolvedValue({ id: 'audit-log-uuid-1' }),
      },
    };

    auditService = new AuditService(mockPrisma as unknown as PrismaService);
  });

  it('creates an audit record with full data', async () => {
    await auditService.log(AuditEventType.REGISTER, {
      userId: 'user-uuid-1',
      email: 'student@phoenix.edu',
      ipAddress: '127.0.0.1',
      userAgent: 'Mozilla/5.0 TestBrowser',
      metadata: { source: 'web' },
    });

    expect(mockPrisma.auditLog.create).toHaveBeenCalledWith({
      data: {
        eventType: AuditEventType.REGISTER,
        userId: 'user-uuid-1',
        email: 'student@phoenix.edu',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 TestBrowser',
        metadata: { source: 'web' },
      },
    });
  });

  it('supports unauthenticated events and sets optional fields to null', async () => {
    await auditService.log(AuditEventType.LOGIN_FAILURE, {
      email: 'unknown@phoenix.edu',
      ipAddress: '192.168.1.1',
      userAgent: 'curl/7.68.0',
      metadata: { reason: 'invalid_credentials' },
    });

    expect(mockPrisma.auditLog.create).toHaveBeenCalledWith({
      data: {
        eventType: AuditEventType.LOGIN_FAILURE,
        userId: null,
        email: 'unknown@phoenix.edu',
        ipAddress: '192.168.1.1',
        userAgent: 'curl/7.68.0',
        metadata: { reason: 'invalid_credentials' },
      },
    });
  });

  it('works when data parameter is omitted', async () => {
    await auditService.log(AuditEventType.LOGOUT);

    expect(mockPrisma.auditLog.create).toHaveBeenCalledWith({
      data: {
        eventType: AuditEventType.LOGOUT,
        userId: null,
        email: null,
        ipAddress: null,
        userAgent: null,
        metadata: undefined,
      },
    });
  });

  it('surfaces persistence errors to callers', async () => {
    mockPrisma.auditLog.create.mockRejectedValue(
      new Error('Database connection failed'),
    );

    await expect(
      auditService.log(AuditEventType.LOGIN_SUCCESS, {
        userId: 'user-uuid-1',
      }),
    ).rejects.toThrow('Database connection failed');
  });
});
