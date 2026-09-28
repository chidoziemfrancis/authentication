import type { KeyObject } from 'node:crypto';
import type { JwksClient } from '../jwt/jwks.client.js';
import type { Duration } from './duration.interface.js';
import type { ClaimRules, JwsAlgorithm } from './jwt.interface.js';

export interface JwksClientOptions {
  /** How long a fetched key set is trusted. Default `'10m'`. */
  cacheTtl?: Duration;
  /**
   * Minimum gap between refetches triggered by an unknown `kid`. Default
   * `'30s'`. Stops a flood of tokens with random `kid`s from turning into a
   * flood of requests to the IdP.
   */
  cooldown?: Duration;
  /** Request timeout. Default `'5s'`. */
  timeout?: Duration;
  fetch?: typeof fetch;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export interface JwtVerifierOptions extends ClaimRules {
  /**
   * A static key: an HS256 secret (at least 32 bytes), or a public or
   * private key as a `KeyObject` or PEM text (a string or a `Buffer`). A
   * public key needs `issuer` and `audience`, as a `jwks` does: it is an
   * identity provider's, which signs the tokens of all its clients with it.
   * A JWK, or DER, is refused (read as bytes, it would be an HS256 secret):
   * pass `createPublicKey({ key: jwk, format: 'jwk' })`.
   */
  key?: KeyObject | string | Buffer;
  /**
   * A JWKS URL, or a shared {@link JwksClient}. Needs `issuer` and
   * `audience`: an identity provider's keys sign the tokens of every one of
   * its clients.
   */
  jwks?: string | JwksClient;
  /**
   * Accepted `alg` values. Defaults: `['HS256']` for a secret, the key's own
   * algorithm for an asymmetric key, `['RS256', 'ES256']` for a JWKS.
   * `none` is never accepted.
   */
  algorithms?: JwsAlgorithm[];
  /** Required `typ` header, e.g. `at+jwt` (RFC 9068). Not checked by default. */
  type?: string;
}

export interface JwtSignerOptions {
  /**
   * An HS256 secret (at least 32 bytes), or a private key for RS256, ES256
   * or EdDSA: a `KeyObject`, or PEM text (a string or a `Buffer`). A JWK, or
   * DER, is refused: pass `createPrivateKey({ key: jwk, format: 'jwk' })`.
   */
  key: KeyObject | string | Buffer;
  /** Default: HS256 for a secret, the key's own algorithm for a private key. */
  alg?: JwsAlgorithm;
  /** Published in the header so verifiers can pick the key from a JWKS. */
  kid?: string;
  issuer?: string;
  audience?: string | string[];
  /** Lifetime of a token. Default `'15m'`: access tokens should be short-lived. */
  ttl?: Duration;
  /** `typ` header. Default `JWT`; RFC 9068 access tokens use `at+jwt`. */
  type?: string;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export interface JwtBearerProviderOptions extends JwtVerifierOptions {
  /** `realm` in the `WWW-Authenticate` challenge. Default `api`. */
  realm?: string;
}
