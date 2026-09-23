import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';

@Module({
  imports: [JwtModule.register({})],
  providers: [PasswordService, TokenService],
  exports: [PasswordService, TokenService],
})
export class AuthModule {}
