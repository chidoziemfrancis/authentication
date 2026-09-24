import { AuthenticationError } from './authentication.error.js';

/**
 * Thrown by `MfaService.enroll()` when the user already has a confirmed
 * authenticator and `replace` was not requested: overwriting it would turn
 * the second factor off until the new one is confirmed. A route that lets
 * it escape answers 409 on any transport. To replace an authenticator, call
 * `enroll(…, { replace: true })` from a step-up route
 * (`@Authenticate({ mfa: true })`), or `disable()` first.
 */
export class MfaAlreadyEnrolledError extends AuthenticationError {
  override readonly status = 409;

  constructor(readonly userId: string) {
    super('Authenticator already enrolled');
    this.name = 'MfaAlreadyEnrolledError';
  }
}
