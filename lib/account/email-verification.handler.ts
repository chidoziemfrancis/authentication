import type { EmailVerificationLink } from '../interfaces/email-verification.interface.js';
import { hasVerifiedEmail } from './email.util.js';

/**
 * Implemented by the app: delivers verification links, and records a
 * verified address in the app's users table (the module ships no mailer and
 * never reads that table). An ordinary provider of one of your modules,
 * which registers itself from its constructor:
 * `registry.registerHandler('emailVerification', this)`.
 */
export abstract class EmailVerificationHandler {
  abstract send(link: EmailVerificationLink): void | Promise<void>;

  /**
   * Marks the user's address verified, but only if it is still `email`
   * (one conditional update: `UPDATE users SET email_verified = true WHERE
   * id = ? AND email = ?`). Resolves `false` when the address changed since
   * the link was sent, or the user is gone: the link then verifies nothing.
   */
  abstract markVerified(userId: string, email: string): boolean | Promise<boolean>;

  /**
   * Whether a signed-in user's current address is verified, for
   * `@Authenticate({ verifiedEmail: true })`. Default: `user.emailVerified === true`.
   */
  isVerified(user: unknown): boolean | Promise<boolean> {
    return hasVerifiedEmail(user);
  }
}
