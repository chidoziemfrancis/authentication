import { KeyObject, createPublicKey, type JsonWebKey } from 'node:crypto';
import { durationOr } from '../utils/duration.util.js';
import { JwtError } from '../errors/jwt.error.js';
import type { JwsAlgorithm } from '../interfaces/jwt.interface.js';
import type { JwksClientOptions } from '../interfaces/jwt-options.interface.js';
import { ASYMMETRIC_ALGORITHMS, type JwsHeader } from './jws.util.js';

interface CachedKey {
  kid?: string;
  alg?: string;
  algorithms: JwsAlgorithm[];
  key: KeyObject;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/** The algorithm of each curve a JWK can name (`crv`, RFC 7518 §6.2.1.1). Other curves are skipped. */
const EC_ALGORITHMS: Record<string, JwsAlgorithm> = { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' };

/**
 * What a JWK can verify, by its type and curve. An RSA key serves every RS and
 * PS algorithm: its `alg`, when published, narrows that, and the verifier's
 * `algorithms` decide which of them are accepted at all.
 */
function algorithmsFor(jwk: JsonWebKey): JwsAlgorithm[] {
  if (jwk.kty === 'RSA') {
    return ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
  }
  if (jwk.kty === 'EC' && jwk.crv && EC_ALGORITHMS[jwk.crv]) {
    return [EC_ALGORITHMS[jwk.crv]];
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return ['EdDSA'];
  }
  return [];
}

/**
 * A cached JSON Web Key Set, shared by bearer-token verification and OIDC
 * ID tokens.
 *
 * - Keys are cached for `cacheTtl`; an unknown `kid` triggers a refetch
 *   (key rotation), at most once per `cooldown`.
 * - Concurrent refreshes share one request.
 * - A failed refresh keeps serving the previous keys. With no keys to
 *   serve, it is an outage (a plain `Error`, so a 500, never a 401 that
 *   would make clients drop valid tokens), retried at most once per
 *   `cooldown`.
 * - Keys marked `use` ≠ `sig`, with `key_ops` lacking `verify`, of
 *   unsupported types, or whose `alg` disagrees with the token are ignored.
 */
export class JwksClient {
  private keys: CachedKey[] = [];
  private fetchedAt = -Infinity;
  private attemptedAt = -Infinity;
  private failure?: Error;
  private inflight?: Promise<void>;
  private readonly options: { cacheTtl: number; cooldown: number; timeout: number } &
    Pick<JwksClientOptions, 'fetch' | 'now'>;

  /** Number of network fetches, for tests and metrics. */
  fetchCount = 0;

  constructor(
    readonly uri: string,
    options: JwksClientOptions = {},
  ) {
    let url: URL | undefined;
    try {
      url = new URL(uri);
    } catch {
      url = undefined;
    }
    // Whoever serves the key set decides which tokens verify: never over plain http, but on loopback.
    if (!url || (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname)))) {
      throw new TypeError(`JwksClient: the key set must be an https URL (http only on loopback), got ${JSON.stringify(uri)}.`);
    }

    this.options = {
      ...options,
      cacheTtl: durationOr(options.cacheTtl, '10m'),
      cooldown: durationOr(options.cooldown, '30s'),
      timeout: durationOr(options.timeout, '5s'),
    };
  }

  async getKey(header: Pick<JwsHeader, 'alg' | 'kid'>): Promise<KeyObject> {
    const alg = header.alg as JwsAlgorithm;
    if (!ASYMMETRIC_ALGORITHMS.includes(alg)) {
      throw new JwtError('unsupported algorithm');
    }

    if (this.now() - this.fetchedAt >= this.options.cacheTtl) {
      await this.refresh(true);
    }

    let found = this.find(header.kid, alg);
    if (!found && this.now() - this.attemptedAt >= this.options.cooldown) {
      await this.refresh(false);
      found = this.find(header.kid, alg);
    }
    if (!found) {
      throw new JwtError('no matching key');
    }
    return found;
  }

  private find(kid: string | undefined, alg: JwsAlgorithm): KeyObject | undefined {
    const candidates = this.keys.filter(
      (k) => k.algorithms.includes(alg) && (!k.alg || k.alg === alg),
    );
    if (kid !== undefined) {
      return candidates.find((k) => k.kid === kid)?.key;
    }
    // No kid: only unambiguous sets are usable.
    return candidates.length === 1 ? candidates[0].key : undefined;
  }

  private refresh(expired: boolean): Promise<void> {
    this.inflight ??= this.load(expired).finally(() => (this.inflight = undefined));
    return this.inflight;
  }

  private async load(expired: boolean) {
    // Nothing to serve and the last attempt failed recently: do not hammer a provider that is down.
    if (this.failure && this.keys.length === 0 && this.now() - this.attemptedAt < this.options.cooldown) {
      throw this.failure;
    }

    this.attemptedAt = this.now();
    try {
      this.fetchCount++;
      const response = await (this.options.fetch ?? fetch)(this.uri, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.options.timeout),
        redirect: 'error',
      });
      if (!response.ok) {
        throw new Error(`it answered ${response.status}`);
      }

      const body = (await response.json()) as { keys?: unknown };
      if (!Array.isArray(body.keys)) {
        throw new Error('it has no keys array');
      }

      // Each entry on its own: one the client cannot read (null, `key_ops` that is no list) is skipped,
      // and the set's other keys still load.
      this.keys = body.keys.flatMap((entry: unknown) => {
        try {
          if (typeof entry !== 'object' || entry === null) {
            return [];
          }
          const jwk = entry as JsonWebKey & { kid?: unknown; alg?: unknown; use?: unknown; key_ops?: unknown };
          if (jwk.use !== undefined && jwk.use !== 'sig') {
            return [];
          }
          if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify'))) {
            return [];
          }
          const algorithms = algorithmsFor(jwk);
          if (algorithms.length === 0) {
            return [];
          }

          // Only the public members are read; a JWKS that leaks `d` still yields a public key.
          const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicJwk } = jwk;
          const key = createPublicKey({ key: publicJwk as JsonWebKey, format: 'jwk' });
          const kid = typeof jwk.kid === 'string' ? jwk.kid : undefined;
          const alg = typeof jwk.alg === 'string' ? jwk.alg : undefined;
          return [{ kid, alg, algorithms, key }];
        } catch {
          return [];
        }
      });

      this.fetchedAt = this.now();
      this.failure = undefined;
    } catch (error) {
      // Keep serving the last good set; fail only if there is none.
      if (this.keys.length === 0) {
        this.failure = new Error(`JWKS ${this.uri} is unavailable: ${(error as Error).message}`, { cause: error });
        throw this.failure;
      }
      if (expired) {
        this.fetchedAt = this.now() - this.options.cacheTtl + this.options.cooldown;
      }
    }
  }

  private now() {
    return this.options.now?.() ?? Date.now();
  }
}
