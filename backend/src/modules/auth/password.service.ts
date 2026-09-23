import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

export interface PasswordPolicyResult {
  isValid: boolean;
  errors: string[];
}

@Injectable()
export class PasswordService {
  /**
   * Hashes a plaintext password using Argon2id.
   * Cryptographic parameters follow OWASP recommendations.
   * Never stores or logs plaintext passwords.
   */
  async hash(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB memory cost
      timeCost: 3,       // 3 iterations
      parallelism: 4,    // 4 threads
    });
  }

  /**
   * Verifies a plaintext password against an Argon2id hash.
   */
  async verify(password: string, passwordHash: string): Promise<boolean> {
    try {
      return await argon2.verify(passwordHash, password);
    } catch {
      return false;
    }
  }

  /**
   * Validates whether a password satisfies the Phoenix password policy:
   * - Minimum 8 characters
   * - Maximum 128 characters
   * - At least one uppercase letter
   * - At least one lowercase letter
   * - At least one digit
   * - At least one special character
   */
  validatePolicy(password: string): PasswordPolicyResult {
    const errors: string[] = [];

    if (!password || password.length < 8) {
      errors.push('Password must be at least 8 characters long.');
    }
    if (password && password.length > 128) {
      errors.push('Password must not exceed 128 characters.');
    }
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter.');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter.');
    }
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number.');
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
      errors.push('Password must contain at least one special character.');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Helper returning true if password meets all policy requirements.
   */
  isPasswordValid(password: string): boolean {
    return this.validatePolicy(password).isValid;
  }
}
