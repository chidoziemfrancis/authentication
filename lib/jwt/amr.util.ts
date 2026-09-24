/**
 * The `amr` values (RFC 8176) that mean a second factor was presented:
 * `mfa` (what `TokenService` records), `otp` and `hwk`. `JwtBearerProvider`
 * treats a token carrying one as MFA-verified, so `TokenService` never lets
 * an app put one into a token by itself.
 */
export const MFA_AMR_VALUES: readonly string[] = ['mfa', 'otp', 'hwk'];

/** Whether an `amr` claim says a second factor was presented. */
export function hasMfaAmr(amr: unknown): boolean {
  return Array.isArray(amr) && amr.some((method) => typeof method === 'string' && MFA_AMR_VALUES.includes(method));
}
