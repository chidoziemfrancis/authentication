import { createPublicKey, type KeyObject } from 'node:crypto';
import { toMs } from '../utils/duration.util.js';
import { JwtError } from '../errors/jwt.error.js';
import type { JwsAlgorithm, JwtClaims } from '../interfaces/jwt.interface.js';
import type { JwtSignerOptions } from '../interfaces/jwt-options.interface.js';
import type { JwtVerifierOptions } from '../interfaces/jwt-options.interface.js';
import { JwksClient } from './jwks.client.js';
import { algorithmFor, assertKeyFits, decodeJws, toKeyObject, validateClaims, verifySignature } from './jws.util.js';

/**
 * Verifies compact JWS tokens and their registered claims. `verify()`
 * throws {@link JwtError}; a configuration that could not verify anything
 * throws a `TypeError` in the constructor.
 */
export class JwtVerifier {
  private readonly key?: KeyObject;
  private readonly jwks?: JwksClient;
  readonly algorithms: JwsAlgorithm[];

  constructor(private readonly options: JwtVerifierOptions) {
    if (!!options.key === !!options.jwks) {
      throw new TypeError('JwtVerifier: pass exactly one of `key` or `jwks`.');
    }

    if (options.key) {
      this.key = toKeyObject(options.key);
    }
    if (options.jwks) {
      this.jwks = typeof options.jwks === 'string' ? new JwksClient(options.jwks) : options.jwks;
    }

    if (this.key) {
      const implied = algorithmFor(this.key);
      if (!implied) {
        throw new TypeError(`JwtVerifier: ${this.key.asymmetricKeyType} keys are not supported.`);
      }
      this.algorithms = options.algorithms ?? [implied];

      // A private key verifies with its public half.
      const verifying = this.key.type === 'private' ? createPublicKey(this.key) : this.key;
      for (const alg of this.algorithms) {
        assertKeyFits(alg, verifying, 'JwtVerifier');
      }
    } else {
      this.algorithms = options.algorithms ?? ['RS256', 'ES256'];
      if (this.algorithms.includes('HS256')) {
        throw new TypeError('JwtVerifier: HS256 cannot be combined with a JWKS.');
      }
      if (typeof options.issuer !== 'string' || options.audience === undefined) {
        throw new TypeError(
          'JwtVerifier: a `jwks` verifier needs `issuer` and `audience`. An identity provider signs tokens for ' +
            'all of its clients with the same keys, so without them tokens issued to other applications verify ' +
            'too. For tokens that carry no audience, pass `audience: false` and check the claim that names your ' +
            'client in `validate()`.',
        );
      }
    }

    // Invalid durations fail here, not at the first request.
    toMs(options.clockTolerance ?? 0);
    toMs(options.maxAge ?? 0);
  }

  async verify(token: string): Promise<JwtClaims> {
    const decoded = decodeJws(token);
    const { header } = decoded;
    const alg = header.alg as JwsAlgorithm;

    if (!this.algorithms.includes(alg)) {
      throw new JwtError('unsupported algorithm');
    }
    // RFC 7515 §4.1.11: extensions we do not understand must be rejected.
    if (header.crit !== undefined) {
      throw new JwtError('unsupported critical header');
    }
    if (
      this.options.type !== undefined &&
      (typeof header.typ !== 'string' || header.typ.toLowerCase() !== this.options.type.toLowerCase())
    ) {
      throw new JwtError('unexpected token type');
    }

    const key = this.key ?? (await this.jwks!.getKey(header));
    verifySignature(alg, key, decoded);
    validateClaims(decoded.payload, this.options);

    return decoded.payload;
  }
}

/**
 * @internal A verifier for what a `JwtSigner` with these options issues:
 * the same secret, or the public half of its private key, with its
 * algorithm, issuer, audience and `typ`. `overrides` add rules (`maxAge`).
 */
export function verifierForSigner(
  signer: JwtSignerOptions,
  overrides: Omit<JwtVerifierOptions, 'key' | 'jwks'> = {},
): JwtVerifier {
  const key = toKeyObject(signer.key);
  const alg = signer.alg ?? algorithmFor(key);
  return new JwtVerifier({
    issuer: signer.issuer,
    audience: signer.audience,
    type: signer.type,
    now: signer.now,
    ...(alg && { algorithms: [alg] }),
    ...overrides,
    key: key.type === 'private' ? createPublicKey(key) : key,
  });
}
