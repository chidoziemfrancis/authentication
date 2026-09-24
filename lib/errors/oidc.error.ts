export class OidcError extends Error {
  constructor(
    message: string,
    /**
     * `request`: bad or forged callback (400). `verification`: the IdP's
     * answer failed checks (401). `unavailable`: the IdP is down or
     * misconfigured (502), which is no fault of the user's.
     */
    readonly kind: 'request' | 'verification' | 'unavailable',
  ) {
    super(message);
    this.name = 'OidcError';
  }
}
