import { describe, it, expect, beforeEach } from 'vitest';
import { PasswordService } from './password.service.js';

describe('PasswordService', () => {
  let passwordService: PasswordService;

  beforeEach(() => {
    passwordService = new PasswordService();
  });

  describe('Hashing and Verification', () => {
    it('1. Same password produces a valid Argon2 hash', async () => {
      const hash = await passwordService.hash('ValidPass123!');
      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash.startsWith('$argon2id$')).toBe(true);
    });

    it('2. Hash must not equal plaintext password', async () => {
      const plaintext = 'SecretPass123!';
      const hash = await passwordService.hash(plaintext);
      expect(hash).not.toBe(plaintext);
    });

    it('3. Correct password verifies true', async () => {
      const plaintext = 'CorrectPass123!';
      const hash = await passwordService.hash(plaintext);
      const isMatch = await passwordService.verify(plaintext, hash);
      expect(isMatch).toBe(true);
    });

    it('4. Incorrect password verifies false', async () => {
      const hash = await passwordService.hash('CorrectPass123!');
      const isMatch = await passwordService.verify('WrongPassword999!', hash);
      expect(isMatch).toBe(false);
    });

    it('5. Different hashes are produced for the same password where Argon2 salting applies', async () => {
      const plaintext = 'RepeatedPass123!';
      const hash1 = await passwordService.hash(plaintext);
      const hash2 = await passwordService.hash(plaintext);
      expect(hash1).not.toBe(hash2);
      expect(await passwordService.verify(plaintext, hash1)).toBe(true);
      expect(await passwordService.verify(plaintext, hash2)).toBe(true);
    });
  });

  describe('Password Policy Validation', () => {
    it('6. Password policy accepts a valid password', () => {
      const result = passwordService.validatePolicy('ValidP@ssw0rd!');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(passwordService.isPasswordValid('ValidP@ssw0rd!')).toBe(true);
    });

    it('7. Password policy rejects passwords below 8 characters', () => {
      const result = passwordService.validatePolicy('P@s1a');
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters long.');
    });

    it('8. Password policy rejects passwords above 128 characters', () => {
      const longPassword = 'Aa1!' + 'x'.repeat(126);
      const result = passwordService.validatePolicy(longPassword);
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must not exceed 128 characters.');
    });

    it('9. Password policy rejects missing uppercase', () => {
      const result = passwordService.validatePolicy('lowercase123!@#');
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one uppercase letter.');
    });

    it('10. Password policy rejects missing lowercase', () => {
      const result = passwordService.validatePolicy('UPPERCASE123!@#');
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one lowercase letter.');
    });

    it('11. Password policy rejects missing number', () => {
      const result = passwordService.validatePolicy('NoNumberHere!@#');
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one number.');
    });

    it('12. Password policy rejects missing special character', () => {
      const result = passwordService.validatePolicy('NoSpecialChar123');
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one special character.');
    });
  });
});
