import type { PasswordResetAccount, PasswordResetLink } from '../interfaces/password-reset.interface.js';

/**
 * Implemented by the app: finds accounts by address, delivers reset links,
 * and stores new password hashes (the module ships no mailer and never reads
 * your users table). An ordinary provider of one of your modules, which
 * registers itself from its constructor:
 * `registry.registerHandler('passwordReset', this)`.
 */
export abstract class PasswordResetHandler {
  /**
   * The account whose address this is, with the address and the password
   * hash it has stored, or `null`. Called with the address trimmed,
   * lowercased and in Unicode NFC.
   */
  abstract findUser(email: string): PasswordResetAccount | null | Promise<PasswordResetAccount | null>;
  abstract send(link: PasswordResetLink): void | Promise<void>;
  /** Stores the new password's hash (from `PasswordHasher`). */
  abstract updatePassword(userId: string, passwordHash: string): void | Promise<void>;
}
