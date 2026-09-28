/**
 * scrypt parameters. The ones a stored hash names are bounded the same way,
 * since a tampered row could otherwise demand any amount of memory: at most
 * 1 GiB (128·N·r) and 16 times the default work (N·r·p).
 */
export interface PasswordHasherOptions {
  /** log2 of the scrypt cost N, an integer from 10 to 22. Default 17 (OWASP minimum: N=2^17, r=8, p=1; ~128 MiB). */
  logN?: number;
  /** Block size, 1 to 32. Default 8. */
  r?: number;
  /** Parallelism, 1 to 16. Default 1. */
  p?: number;
  /** Derived key length, 16 to 64 bytes. Default 32. */
  keyLength?: number;
  /** Salt length, 16 to 64 bytes. Default 16. */
  saltLength?: number;
}
