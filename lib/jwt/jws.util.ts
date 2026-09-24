import {
  KeyObject,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  timingSafeEqual,
} from 'node:crypto';
import { toMs } from '../utils/duration.util.js';
import type { JwsAlgorithm, JwtClaims, ClaimRules } from '../interfaces/jwt.interface.js';
import { JwtError } from '../errors/jwt.error.js';

export const ASYMMETRIC_ALGORITHMS: readonly JwsAlgorithm[] = ['RS256', 'ES256', 'EdDSA'];

export interface JwsHeader {
  alg: string;
  kid?: string;
  typ?: string;
  crit?: unknown;
  [key: string]: unknown;
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const PEM = /-----BEGIN ([A-Z0-9 ]+)-----/;

/**
 * A key from configuration. PEM text (a string or a `Buffer`: SPKI, PKCS#1,
 * PKCS#8, SEC1, or an X.509 certificate) is read as the key it encodes;
 * only other text is an HMAC secret. Read as a secret, a PEM public key
 * would let anyone who has it, which is everyone, sign HS256 tokens.
 */
export function toKeyObject(key: KeyObject | string | Buffer): KeyObject {
  if (key instanceof KeyObject) {
    return key;
  }

  const text = typeof key === 'string' ? key : key.toString('latin1');
  const pem = PEM.exec(text);
  if (!pem) {
    return createSecretKey(typeof key === 'string' ? Buffer.from(key) : key);
  }

  try {
    return pem[1].includes('PRIVATE KEY') ? createPrivateKey(key) : createPublicKey(key);
  } catch (error) {
    throw new TypeError(`Cannot read the PEM ${pem[1].toLowerCase()}: ${(error as Error).message}`);
  }
}

/** The algorithm a key implies: HS256 for a secret, the key's own for asymmetric keys. */
export function algorithmFor(key: KeyObject): JwsAlgorithm | undefined {
  if (key.type === 'secret') {
    return 'HS256';
  }
  switch (key.asymmetricKeyType) {
    case 'rsa':
      return 'RS256';
    case 'ec':
      return 'ES256';
    case 'ed25519':
      return 'EdDSA';
    default:
      return undefined;
  }
}

/**
 * Whether `key` is appropriate for `alg`. This is the algorithm/key binding
 * that stops key-confusion attacks: an RSA public key can never be used as
 * an HMAC secret, a P-384 key never verifies ES256, and so on.
 */
export function keyFits(alg: JwsAlgorithm, key: KeyObject): boolean {
  const details = key.asymmetricKeyDetails;
  switch (alg) {
    case 'HS256':
      return key.type === 'secret' && (key.symmetricKeySize ?? 0) >= 32;
    case 'RS256':
      return key.asymmetricKeyType === 'rsa' && (details?.modulusLength ?? 0) >= 2048;
    case 'ES256':
      return key.asymmetricKeyType === 'ec' && details?.namedCurve === 'prime256v1';
    case 'EdDSA':
      return key.asymmetricKeyType === 'ed25519';
    default:
      return false;
  }
}

const REQUIREMENTS: Record<JwsAlgorithm, string> = {
  HS256: 'a secret of at least 32 bytes (`openssl rand -base64 32`)',
  RS256: 'an RSA key of at least 2048 bits',
  ES256: 'a P-256 key',
  EdDSA: 'an Ed25519 key',
};

/** Throws a `TypeError` (configuration, not a token) unless `key` can serve `alg`. */
export function assertKeyFits(alg: JwsAlgorithm, key: KeyObject, owner: string): void {
  if (!keyFits(alg, key)) {
    throw new TypeError(`${owner}: the key is not a valid ${alg} key; ${alg} needs ${REQUIREMENTS[alg]}.`);
  }
}

/** Throws a `TypeError` (configuration, not a token) unless `key` can sign `alg`. */
export function assertSigningKey(alg: JwsAlgorithm, key: KeyObject, owner: string): void {
  assertKeyFits(alg, key, owner);
  if (alg !== 'HS256' && key.type !== 'private') {
    throw new TypeError(`${owner}: ${alg} signing needs a private key.`);
  }
}

export function signJws(header: JwsHeader & { alg: JwsAlgorithm }, payload: object, key: KeyObject): string {
  assertSigningKey(header.alg, key, 'JwtSigner');

  const input = `${encode(header)}.${encode(payload)}`;
  const data = Buffer.from(input);
  let signature: Buffer;
  switch (header.alg) {
    case 'HS256':
      signature = createHmac('sha256', key).update(data).digest();
      break;
    case 'RS256':
      signature = cryptoSign('sha256', data, key);
      break;
    case 'ES256':
      signature = cryptoSign('sha256', data, { key, dsaEncoding: 'ieee-p1363' });
      break;
    case 'EdDSA':
      signature = cryptoSign(null, data, key);
      break;
  }

  return `${input}.${signature.toString('base64url')}`;
}

export interface DecodedJws {
  header: JwsHeader;
  payload: JwtClaims;
  signingInput: Buffer;
  signature: Buffer;
}

/** Splits and decodes without verifying. */
export function decodeJws(token: string): DecodedJws {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => SEGMENT.test(p))) {
    throw new JwtError('malformed token');
  }

  const header = decodeJson(parts[0]) as JwsHeader;
  if (typeof header.alg !== 'string') {
    throw new JwtError('malformed token');
  }

  return {
    header,
    payload: decodeJson(parts[1]) as JwtClaims,
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
    signature: Buffer.from(parts[2], 'base64url'),
  };
}

export function verifySignature(alg: JwsAlgorithm, key: KeyObject, decoded: DecodedJws): void {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  if (!keyFits(alg, publicKey)) {
    throw new JwtError(`key is not a valid ${alg} key`);
  }

  const { signingInput, signature } = decoded;
  let valid: boolean;
  switch (alg) {
    case 'HS256': {
      const expected = createHmac('sha256', publicKey).update(signingInput).digest();
      valid = signature.length === expected.length && timingSafeEqual(signature, expected);
      break;
    }
    case 'RS256':
      valid = cryptoVerify('sha256', signingInput, publicKey, signature);
      break;
    case 'ES256':
      // JWS uses the raw r||s form (RFC 7518 §3.4), not DER.
      valid =
        signature.length === 64 &&
        cryptoVerify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
      break;
    case 'EdDSA':
      valid = signature.length === 64 && cryptoVerify(null, signingInput, publicKey, signature);
      break;
    default:
      valid = false;
  }

  if (!valid) {
    throw new JwtError('invalid signature');
  }
}

export function validateClaims(claims: JwtClaims, rules: ClaimRules): void {
  // JWT times are seconds (RFC 7519 §2, NumericDate).
  const now = Math.floor((rules.now?.() ?? Date.now()) / 1000);
  const leeway = toMs(rules.clockTolerance ?? 0) / 1000;

  for (const name of rules.required ?? ['exp']) {
    if (claims[name] === undefined) {
      throw new JwtError(`missing ${name}`);
    }
  }

  for (const name of ['exp', 'nbf', 'iat'] as const) {
    if (claims[name] !== undefined && (typeof claims[name] !== 'number' || !Number.isFinite(claims[name]))) {
      throw new JwtError(`invalid ${name}`);
    }
  }

  // What `JwtClaims` promises `validate()`.
  for (const name of ['iss', 'sub', 'jti'] as const) {
    if (claims[name] !== undefined && typeof claims[name] !== 'string') {
      throw new JwtError(`invalid ${name}`);
    }
  }

  if (claims.exp !== undefined && now >= claims.exp + leeway) {
    throw new JwtError('token expired');
  }
  if (claims.nbf !== undefined && now < claims.nbf - leeway) {
    throw new JwtError('token not yet valid');
  }
  if (claims.iat !== undefined && claims.iat > now + leeway) {
    throw new JwtError('token issued in the future');
  }

  if (rules.maxAge !== undefined) {
    if (claims.iat === undefined) {
      throw new JwtError('missing iat');
    }
    if (now - claims.iat > toMs(rules.maxAge) / 1000 + leeway) {
      throw new JwtError('token too old');
    }
  }

  if (rules.issuer !== undefined && claims.iss !== rules.issuer) {
    throw new JwtError('unexpected issuer');
  }

  if (rules.audience !== undefined && rules.audience !== false) {
    const accepted = ([] as string[]).concat(rules.audience);
    const given = ([] as unknown[]).concat(claims.aud ?? []);
    if (!given.some((aud) => typeof aud === 'string' && accepted.includes(aud))) {
      throw new JwtError('unexpected audience');
    }
  }
}

function encode(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function decodeJson(segment: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('malformed token');
  }

  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new JwtError('malformed token');
  }
  return value as Record<string, unknown>;
}
