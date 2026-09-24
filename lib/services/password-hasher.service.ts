import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';
import type { PasswordHasherOptions } from '../interfaces/password-hasher-options.interface.js';

interface Params {
  logN: number;
  r: number;
  p: number;
}

// $scrypt$ln=17,r=8,p=1$<salt>$<hash>, unpadded standard base64 as in the PHC string format.
const FORMAT = /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,3}),p=(\d{1,3})\$([A-Za-z0-9+/]{16,})\$([A-Za-z0-9+/]{16,})$/;
const MAX_PASSWORD_BYTES = 4096;

function scrypt(password: Buffer, salt: Buffer, keyLength: number, { logN, r, p }: Params): Promise<Buffer> {
  const N = 2 ** logN;
  const options: ScryptOptions = { N, r, p, maxmem: 256 * N * r + 1024 * 1024 };
  return new Promise((resolve, reject) =>
    scryptCb(password, salt, keyLength, options, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

const b64 = (buf: Buffer) => buf.toString('base64').replace(/=+$/, '');

/**
 * scrypt password hashing (Node's `crypto.scrypt`, run on the libuv
 * threadpool so it does not block the event loop).
 *
 * The encoded hash is self-describing (`$scrypt$ln=17,r=8,p=1$salt$hash`),
 * so parameters can be raised later: `verify()` reads the parameters from
 * the stored hash and `needsRehash()` tells the sign-in code to store a
 * fresh hash while it has the plaintext.
 *
 * Passwords are NFKC-normalised (NIST SP 800-63B §5.1.1.2) so the same
 * password typed on different keyboards verifies.
 *
 * The module provides one built from its `password` option. Tests replace
 * it with a cheaper one: `new PasswordHasher({ logN: 10 })`.
 */
export class PasswordHasher {
  private readonly params: Params;
  private readonly keyLength: number;
  private readonly saltLength: number;
  private dummy?: Promise<string>;

  constructor(options: PasswordHasherOptions = {}) {
    this.params = { logN: options.logN ?? 17, r: options.r ?? 8, p: options.p ?? 1 };
    this.keyLength = options.keyLength ?? 32;
    this.saltLength = options.saltLength ?? 16;
    if (!isSane(this.params)) {
      throw new RangeError('PasswordHasher: unsupported scrypt parameters');
    }
  }

  async hash(password: string): Promise<string> {
    const input = this.encodeInput(password);
    const salt = randomBytes(this.saltLength);
    const key = await this.derive(input, salt, this.keyLength, this.params);
    const { logN, r, p } = this.params;
    return `$scrypt$ln=${logN},r=${r},p=${p}$${b64(salt)}$${b64(key)}`;
  }

  /**
   * Constant-time check. Pass `undefined` for an unknown user: a dummy hash
   * is checked instead, so response time does not reveal which accounts
   * exist. The first such call makes the dummy hash, which costs the same
   * one derivation as every later check.
   */
  async verify(password: string, encoded: string | null | undefined): Promise<boolean> {
    if (!encoded) {
      if (!this.dummy) {
        this.dummy = this.hash('dummy password for timing equalisation');
        await this.dummy;
      } else {
        await this.verify(password, await this.dummy);
      }
      return false;
    }

    const parsed = parse(encoded);
    if (!parsed) {
      return false;
    }

    let input: Buffer;
    try {
      input = this.encodeInput(password);
    } catch {
      return false;
    }

    const actual = await this.derive(input, parsed.salt, parsed.hash.length, parsed.params);
    return timingSafeEqual(actual, parsed.hash);
  }

  /** `true` when the stored hash uses weaker or different parameters than configured. */
  needsRehash(encoded: string): boolean {
    const parsed = parse(encoded);
    if (!parsed) {
      return true;
    }

    const { logN, r, p } = parsed.params;
    return (
      logN !== this.params.logN ||
      r !== this.params.r ||
      p !== this.params.p ||
      parsed.hash.length !== this.keyLength ||
      parsed.salt.length < this.saltLength
    );
  }

  /** The one expensive step: scrypt on the libuv threadpool. */
  private derive(input: Buffer, salt: Buffer, keyLength: number, params: Params): Promise<Buffer> {
    return scrypt(input, salt, keyLength, params);
  }

  private encodeInput(password: string): Buffer {
    if (typeof password !== 'string') {
      throw new TypeError('password must be a string');
    }

    const input = Buffer.from(password.normalize('NFKC'), 'utf8');
    if (input.length > MAX_PASSWORD_BYTES) {
      throw new RangeError('password too long');
    }
    return input;
  }
}

function isSane({ logN, r, p }: Params): boolean {
  // Bounds also cap what a tampered stored hash can make us compute.
  return logN >= 10 && logN <= 22 && r >= 1 && r <= 32 && p >= 1 && p <= 16;
}

function parse(encoded: string): { params: Params; salt: Buffer; hash: Buffer } | undefined {
  const match = FORMAT.exec(encoded);
  if (!match) {
    return undefined;
  }

  const params = { logN: Number(match[1]), r: Number(match[2]), p: Number(match[3]) };
  if (!isSane(params)) {
    return undefined;
  }

  const salt = Buffer.from(match[4], 'base64');
  const hash = Buffer.from(match[5], 'base64');
  if (hash.length < 16 || hash.length > 64) {
    return undefined;
  }

  return { params, salt, hash };
}
