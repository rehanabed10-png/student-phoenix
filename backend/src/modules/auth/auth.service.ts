import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response } from 'express';
import { PrismaService } from '../../common/prisma/prisma.service.js';
import { UsersService } from '../users/users.service.js';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { AuthResponseDto } from './dto/auth-response.dto.js';
import {
  REFRESH_TOKEN_COOKIE_NAME,
  getRefreshTokenCookieOptions,
} from './utils/cookies.util.js';

export interface AuthenticationResult {
  authResponse: AuthResponseDto;
  rawRefreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
  ) {}

  /**
   * Registers a new student account, verifies password policy,
   * creates the user with the STUDENT role, and issues tokens.
   */
  async register(dto: RegisterDto): Promise<AuthenticationResult> {
    // Validate password policy
    const policyResult = this.passwordService.validatePolicy(dto.password);
    if (!policyResult.isValid) {
      throw new BadRequestException(policyResult.errors.join(' '));
    }

    // Hash password with Argon2id
    const passwordHash = await this.passwordService.hash(dto.password);

    // Create student user via UsersService (enforces STUDENT role, handles duplicates)
    const user = await this.usersService.createStudentUser({
      email: dto.email,
      passwordHash,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });

    // Generate tokens and persist refresh session
    return this.createAuthSession(user);
  }

  /**
   * Authenticates a user by email and password, issuing access and refresh tokens.
   * Generic error message prevents account enumeration.
   */
  async login(dto: LoginDto): Promise<AuthenticationResult> {
    const normalizedEmail = dto.email.toLowerCase().trim();
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    const isPasswordValid = await this.passwordService.verify(
      dto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    return this.createAuthSession(user);
  }

  /**
   * Sets the HttpOnly refresh token cookie on the outgoing HTTP response.
   */
  setRefreshTokenCookie(res: Response, rawRefreshToken: string): void {
    const maxAgeMs = this.tokenService.getRefreshTokenExpiresInMs();
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      rawRefreshToken,
      getRefreshTokenCookieOptions(maxAgeMs),
    );
  }

  /**
   * Internal helper: issues an access token and persists a hashed refresh token session.
   */
  private async createAuthSession(user: any): Promise<AuthenticationResult> {
    // Generate short-lived JWT access token
    const accessToken = this.tokenService.generateAccessToken({
      sub: user.id,
      email: user.email,
      role: user.role.name,
    });

    // Generate cryptographically secure refresh token
    const rawRefreshToken = this.tokenService.generateRefreshToken();
    const tokenHash = this.tokenService.hashRefreshToken(rawRefreshToken);

    // Store only the token hash in the database with configured expiration
    await this.prisma.refreshToken.create({
      data: {
        tokenHash,
        userId: user.id,
        expiresAt: this.tokenService.getRefreshTokenExpiresAt(),
      },
    });

    return {
      authResponse: {
        accessToken,
        user: this.usersService.sanitizeUser(user),
      },
      rawRefreshToken,
    };
  }
}
