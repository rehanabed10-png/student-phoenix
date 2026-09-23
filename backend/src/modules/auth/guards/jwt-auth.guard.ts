import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * JwtAuthGuard protects routes requiring valid JWT access token authentication.
 * Relies on Passport JWT strategy for Bearer token extraction and validation.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
