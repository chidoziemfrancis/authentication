export interface PasswordHasherOptions {
  /** log2 of the scrypt cost N. Default 17 (OWASP minimum: N=2^17, r=8, p=1; ~128 MiB). */
  logN?: number;
  /** Block size. Default 8. */
  r?: number;
  /** Parallelism. Default 1. */
  p?: number;
  /** Derived key length, bytes. Default 32. */
  keyLength?: number;
  /** Salt length, bytes. Default 16. */
  saltLength?: number;
}
