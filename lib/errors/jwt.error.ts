import { AuthenticationError } from './authentication.error.js';

/**
 * A token failed verification: malformed, badly signed, expired, for
 * another issuer or audience. An {@link AuthenticationError} (401), so a
 * route that lets one escape answers 401 on any transport.
 */
export class JwtError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'JwtError';
  }
}
