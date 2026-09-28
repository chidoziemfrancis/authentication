/** @internal What `@Authenticate({ verifiedEmail: true })` checks without a handler. */
export function hasVerifiedEmail(user: unknown): boolean {
  return typeof user === 'object' && user !== null && (user as { emailVerified?: unknown }).emailVerified === true;
}

/**
 * @internal The address as links carry it: trimmed, lowercased, and in
 * Unicode NFC, so an address typed with a combining accent is the same
 * address as the one stored precomposed.
 */
export function normalizeEmail(email: string): string {
  if (typeof email !== 'string') {
    throw new TypeError('An email address must be a string');
  }
  return email.trim().normalize('NFC').toLowerCase();
}

/**
 * @internal An address worth mailing a link to: `local@domain`, at most 254
 * characters (RFC 5321 §4.5.3.1.3), without whitespace or control
 * characters, which a mailer could take for header syntax.
 */
export function isMailableEmail(normalized: string): boolean {
  // oxlint-disable-next-line no-control-regex -- control characters are what it refuses
  if (normalized.length > 254 || /[\s\x00-\x1f\x7f]/.test(normalized)) {
    return false;
  }
  const at = normalized.lastIndexOf('@');
  return at > 0 && at < normalized.length - 1;
}
