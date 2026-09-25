import { randomBytes } from 'node:crypto';
import type { ExecutionContext } from '@nestjs/common';
import { AuthenticationError } from '../errors/authentication.error.js';
import type {
  ApiKeyProviderOptions,
  ApiKeyRecord,
  ApiKeySession,
  GeneratedApiKey,
} from '../interfaces/api-key.interface.js';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';
import { API_KEY_PATTERN, API_KEY_PREFIX_PATTERN } from '../utils/api-key.util.js';
import { bearerToken } from '../utils/bearer.util.js';
import { randomToken, safeEqual, sha256 } from '../utils/crypto.util.js';
import { AuthenticationProvider } from './authentication.provider.js';

/** Compared against when the id is unknown, so every key costs the same hashing. */
const NO_KEY = sha256('');

/**
 * Base class for API keys: `Authorization: Bearer <prefix>_<id>_<secret>`,
 * for scripts and partner systems. Extend it and look a key up by its id in
 * your own table:
 *
 * ```ts
 * @Injectable()
 * export class ApiKeyAuth extends ApiKeyProvider<User> {
 *   constructor(private readonly apiKeysRepository: ApiKeysRepository, registry: AuthenticationRegistry) {
 *     super({ prefix: 'cat' });
 *     registry.registerProvider(this, { order: 2 });
 *   }
 *   findKey(id: string) {
 *     return this.apiKeysRepository.findWithUser(id); // { hash, user, expiresAt } or null
 *   }
 * }
 * ```
 *
 * `generate()` makes a key: show the whole key once, and store its `id` and
 * `hash`. Keys carry 256 random bits, so a SHA-256 of the key is all the
 * store needs (a slow hash would only cost CPU on every request), and the
 * hash is compared in constant time, with the same work for an unknown id.
 *
 * A key signs its user in on every route, but never counts as a second
 * factor: `@Authenticate({ mfa: true })` refuses it. Keep keys to the routes
 * meant for them with `@Authenticate({ providers })`. Permissions per key
 * are authorization's job (`@nestjs/authorization`), with the key id from
 * the session. Tokens without this provider's prefix are left to the other
 * providers; a JWT never looks like a key, so `JwtBearerProvider` can run
 * before or after this one.
 */
export abstract class ApiKeyProvider<TUser> extends AuthenticationProvider<TUser, ApiKeySession> {
  private readonly prefix: string;
  private readonly realm: string;
  private readonly now: () => number;

  constructor({ prefix, realm = 'api', now = Date.now }: ApiKeyProviderOptions) {
    super();
    if (typeof prefix !== 'string' || !API_KEY_PREFIX_PATTERN.test(prefix)) {
      throw new TypeError(
        `${new.target.name}: \`prefix\` must be 1-16 lowercase letters and digits, starting with a letter ` +
          `(e.g. 'cat' for cat_<id>_<secret>), got ${JSON.stringify(prefix)}.`,
      );
    }

    this.prefix = prefix;
    this.realm = realm;
    this.now = now;
  }

  /**
   * The key with this id, as stored, or `null` for none: unknown, revoked,
   * or its user is gone. The provider checks the hash and `expiresAt`.
   */
  protected abstract findKey(
    id: string,
  ): ApiKeyRecord<TUser> | null | undefined | Promise<ApiKeyRecord<TUser> | null | undefined>;

  /** A new key with this provider's prefix. */
  generate(): GeneratedApiKey {
    const id = randomBytes(8).toString('hex');
    const key = `${this.prefix}_${id}_${randomToken()}`;
    return { key, id, hash: sha256(key) };
  }

  async authenticate(context: ExecutionContext): Promise<AuthenticationResult<TUser, ApiKeySession> | null> {
    const token = bearerToken(context, this.header(context, 'authorization'));
    if (token === null) {
      this.reject('malformed authorization header');
    }
    if (token === undefined || !token.startsWith(`${this.prefix}_`)) {
      return null;
    }

    const match = API_KEY_PATTERN.exec(token);
    if (!match) {
      this.reject('malformed api key');
    }

    const id = match[2];
    const record = await this.findKey(id);
    // Hash and compare whether or not the id exists.
    const matches = safeEqual(sha256(token), typeof record?.hash === 'string' ? record.hash : NO_KEY);
    if (!record || !matches || record.user === null || record.user === undefined) {
      this.reject('invalid api key');
    }

    const expiresAt = record.expiresAt ?? undefined;
    if (expiresAt && expiresAt.getTime() <= this.now()) {
      this.reject('api key expired');
    }

    const session: ApiKeySession = { method: 'api-key', keyId: id, ...(expiresAt && { expiresAt }) };
    return { user: record.user, session };
  }

  challenge(): string {
    return `Bearer realm="${this.realm}"`;
  }

  private reject(description: string): never {
    // RFC 6750 §3.1, as JwtBearerProvider answers
    throw new AuthenticationError(description, {
      challenge: `Bearer realm="${this.realm}", error="invalid_token", error_description="${description}"`,
    });
  }
}
