import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { requireOption } from '../utils/options.util.js';
import type { SecretEncryptionOptions } from '../interfaces/mfa-options.interface.js';
import { SecretDecryptionError } from '../errors/secret-decryption.error.js';

const VERSION = 'v1';
const HKDF_INFO = 'nestjs-authentication totp-secret v1';
const MIN_SECRET_LENGTH = 32;
const OPTION = 'mfa.encryption.keys';

/**
 * AES-256-GCM for secrets the server must read back (TOTP seeds cannot be
 * hashed). Format: `v1.<keyId>.<iv>.<ciphertext>.<tag>`, base64url parts.
 *
 * - The key id is derived from the key (8 characters of its SHA-256), so
 *   rotation finds the right key without anyone naming keys, and the id
 *   reveals nothing about the key.
 * - A fresh 96-bit IV per encryption (NIST SP 800-38D §8.2.2 random IVs;
 *   fine far below 2^32 encryptions per key).
 * - Additional authenticated data binds the version, key id, purpose and
 *   owner (`v1.<keyId>.<context>`), so a ciphertext copied to another user's
 *   row, or with a rewritten header, fails authentication.
 * - Decryption fails closed: any malformed value, unknown key id or bad tag
 *   throws {@link SecretDecryptionError}.
 */
export class SecretCipher {
  private readonly keys = new Map<string, Buffer>();
  private readonly currentId: string;

  constructor(private readonly options: SecretEncryptionOptions) {
    const list: unknown = options?.keys;
    if (!Array.isArray(list) || list.length === 0) {
      throw new TypeError(`MFA: \`${OPTION}\` must list at least one key (newest first).`);
    }

    const derived = list.map(deriveKey);
    // A key listed twice has one id: the first entry wins, and both are the same key.
    for (const { id, key } of derived) {
      if (!this.keys.has(id)) {
        this.keys.set(id, key);
      }
    }

    this.currentId = derived[0].id;
  }

  encrypt(plaintext: string, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.keys.get(this.currentId)!, iv);
    cipher.setAAD(aad(this.currentId, context));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return [VERSION, this.currentId, iv, ciphertext, cipher.getAuthTag()]
      .map((part) => (typeof part === 'string' ? part : part.toString('base64url')))
      .join('.');
  }

  decrypt(stored: string, context: string): { plaintext: string; needsReencrypt: boolean } {
    if (!stored.startsWith(`${VERSION}.`)) {
      if (this.options.migratePlaintext) {
        return { plaintext: stored, needsReencrypt: true };
      }
      throw new SecretDecryptionError('value is not encrypted');
    }

    const parts = stored.split('.');
    if (parts.length !== 5) {
      throw new SecretDecryptionError('malformed ciphertext');
    }

    const [, keyId, iv, ciphertext, tag] = parts.map((p, i) => (i < 2 ? p : Buffer.from(p, 'base64url'))) as [
      string,
      string,
      Buffer,
      Buffer,
      Buffer,
    ];

    const key = this.keys.get(keyId);
    if (!key) {
      throw new SecretDecryptionError(`unknown key id '${keyId}'`);
    }
    if (iv.length !== 12 || tag.length !== 16) {
      throw new SecretDecryptionError('malformed ciphertext');
    }

    try {
      const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
      decipher.setAAD(aad(keyId, context));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      return { plaintext, needsReencrypt: keyId !== this.currentId };
    } catch {
      throw new SecretDecryptionError('authentication failed');
    }
  }

  needsReencrypt(stored: string): boolean {
    return !stored.startsWith(`${VERSION}.${this.currentId}.`);
  }
}

function aad(keyId: string, context: string) {
  return Buffer.from(`${VERSION}.${keyId}.${context}`, 'utf8');
}

/** The AES key for one `keys` entry, and its id. Errors name the entry, never its value. */
function deriveKey(material: unknown, index: number): { id: string; key: Buffer } {
  const option = `${OPTION}[${index}]`;
  requireOption(material, option, `32 random bytes, or a random string of at least ${MIN_SECRET_LENGTH} characters`);

  let key: Buffer;
  if (Buffer.isBuffer(material)) {
    if (material.length !== 32) {
      throw new TypeError(`MFA: \`${option}\` is a Buffer of ${material.length} bytes; it must be 32 bytes.`);
    }
    key = material;
  } else if (typeof material === 'string' && material.length >= MIN_SECRET_LENGTH) {
    key = Buffer.from(hkdfSync('sha256', material, Buffer.alloc(0), HKDF_INFO, 32));
  } else {
    throw new TypeError(
      `MFA: \`${option}\` must be 32 random bytes, or a random string of at least ${MIN_SECRET_LENGTH} ` +
        'characters (for example `openssl rand -base64 32`), not a password.',
    );
  }

  const id = createHash('sha256').update(key).digest('base64url').slice(0, 8);
  return { id, key };
}
