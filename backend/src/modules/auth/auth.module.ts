import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from '../../common/prisma/prisma.module.js';
import { UsersModule } from '../users/users.module.js';
import { AuditModule } from '../audit/audit.module.js';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { JwtStrategy } from './jwt.strategy.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { RolesGuard } from './guards/roles.guard.js';
import { AuthService } from './auth.service.js';
import { AuthController } from './auth.controller.js';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({}),
    PrismaModule,
    UsersModule,
    AuditModule,
  ],
  controllers: [AuthController],
  providers: [
    PasswordService,
    TokenService,
    JwtStrategy,
    JwtAuthGuard,
    RolesGuard,
    AuthService,
  ],
  exports: [
    AuthService,
    PasswordService,
    TokenService,
    JwtAuthGuard,
    RolesGuard,
  ],
})
export class AuthModule {}


