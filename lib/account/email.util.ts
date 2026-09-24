/** @internal What `@Authenticate({ verifiedEmail: true })` checks without a handler. */
export function hasVerifiedEmail(user: unknown): boolean {
  return typeof user === 'object' && user !== null && (user as { emailVerified?: unknown }).emailVerified === true;
}

/** @internal The address as links carry it: trimmed, lowercased. */
export function normalizeEmail(email: string): string {
  if (typeof email !== 'string') {
    throw new TypeError('An email address must be a string');
  }
  return email.trim().toLowerCase();
}
