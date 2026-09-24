import type { RefreshTokenFailure } from '../interfaces/refresh-token-options.interface.js';
import { AuthenticationError } from './authentication.error.js';

/**
 * A refresh token was refused. An {@link AuthenticationError}, so a route
 * that lets it escape answers 401 on any transport.
 */
export class RefreshTokenError extends AuthenticationError {
  constructor(readonly reason: RefreshTokenFailure) {
    super(`Refresh token ${reason}`);
    this.name = 'RefreshTokenError';
  }
}
