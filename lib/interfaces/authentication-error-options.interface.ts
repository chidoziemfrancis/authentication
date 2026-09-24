export interface AuthenticationErrorOptions {
  /** `WWW-Authenticate` challenge sent with the 401 over HTTP, e.g. `ApiKey header="x-api-key"`. */
  challenge?: string;
  /** Machine-readable reason, sent as the body's `error` field (`mfa_required`). */
  code?: string;
  /** The error behind this one, for logs. */
  cause?: unknown;
}
