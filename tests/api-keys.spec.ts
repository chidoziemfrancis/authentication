/**
 * `ApiKeyProvider` on its own: the key format and its entropy, verification (right key, wrong
 * secret, unknown or revoked id, malformed, expired), the constant-time path, the transports it
 * reads a key from, and `JwtBearerProvider` leaving keys to it.
 */
import { createHash } from 'node:crypto';
import type { ExecutionContext } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/internal';
import { ApiKeyProvider, AuthenticationError, JwtBearerProvider, type ApiKeyRecord, type JwtClaims } from '../lib/index.js';

const crypto = vi.hoisted(() => ({ hashes: 0, comparisons: 0 }));
vi.mock('node:crypto', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:crypto')>();
  return {
    ...original,
    createHash: (...args: Parameters<typeof original.createHash>) => {
      crypto.hashes++;
      return original.createHash(...args);
    },
    timingSafeEqual: (...args: Parameters<typeof original.timingSafeEqual>) => {
      crypto.comparisons++;
      return original.timingSafeEqual(...args);
    },
  };
});

type User = { id: string };

const NOW = 1_800_000_000_000;
const KEY_FORMAT = /^cat_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/;

class Handler {
  handle() {}
}

function contextOf(type: 'http' | 'ws' | 'rpc', first: object): ExecutionContext {
  const context = new ExecutionContextHost([first, {}], Handler, Handler.prototype.handle);
  context.setType(type);
  return context;
}

const http = (headers: Record<string, string>) => contextOf('http', { headers });
const bearer = (token: string) => http({ authorization: `Bearer ${token}` });

/** Keys in a map, as a table would hold them: `id` → the stored hash, user and expiry. */
class CatKeys extends ApiKeyProvider<User> {
  readonly rows = new Map<string, ApiKeyRecord<User>>();
  readonly lookups: string[] = [];

  constructor(options: { realm?: string } = {}) {
    super({ prefix: 'cat', now: () => NOW, ...options });
  }

  findKey(id: string) {
    this.lookups.push(id);
    return this.rows.get(id) ?? null;
  }

  /** A new key for `userId`, stored as the app stores it: the id and the hash only. */
  add(userId: string, expiresAt?: Date | null) {
    const { key, id, hash } = this.generate();
    this.rows.set(id, { hash, user: { id: userId }, expiresAt });
    return { key, id };
  }
}

async function rejection(promise: Promise<unknown>): Promise<AuthenticationError> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(AuthenticationError);
  return error as AuthenticationError;
}

const challenge = (description: string, realm = 'api') =>
  `Bearer realm="${realm}", error="invalid_token", error_description="${description}"`;

describe('ApiKeyProvider.generate()', () => {
  it('makes <prefix>_<id>_<secret> keys, and stores nothing but the id and the SHA-256 of the key', () => {
    const { key, id, hash } = new CatKeys().generate();
    expect(key).toMatch(KEY_FORMAT);
    expect(key.split('_')[1]).toBe(id);
    expect(hash).toBe(createHash('sha256').update(key).digest('base64url'));
    expect(hash).not.toContain(key.slice(-43));
  });

  it('draws a 64-bit id and a 256-bit secret for each key', () => {
    const provider = new CatKeys();
    const keys = Array.from({ length: 1000 }, () => provider.generate());
    expect(new Set(keys.map((k) => k.id)).size).toBe(1000);
    expect(new Set(keys.map((k) => k.key.slice(-43))).size).toBe(1000);
    expect(Buffer.from(keys[0].key.slice(-43), 'base64url')).toHaveLength(32);
    expect(Buffer.from(keys[0].id, 'hex')).toHaveLength(8);

    // Every hex digit and every base64url character turns up: nothing is fixed.
    expect(new Set(keys.flatMap((k) => [...k.id])).size).toBe(16);
    expect(new Set(keys.flatMap((k) => [...k.key.slice(-43)])).size).toBe(64);
  });

  it('refuses a prefix that would make keys ambiguous or hard to scan for, naming the class', () => {
    class Keys extends ApiKeyProvider<User> {
      findKey() {
        return null;
      }
    }
    for (const prefix of ['', 'Cat', 'c_t', '1cat', 'cat-live', 'abcdefghijklmnopq', undefined as never]) {
      expect(() => new Keys({ prefix })).toThrow(/^Keys: `prefix` must be 1-16 lowercase letters and digits/);
    }
    for (const prefix of ['c', 'cat', 'catlive2', 'abcdefghijklmnop']) {
      expect(new Keys({ prefix }).generate().key.startsWith(`${prefix}_`)).toBe(true);
    }
  });
});

describe('ApiKeyProvider: verification', () => {
  it('signs a key in as its user, with the key id in the session and no second factor', async () => {
    const provider = new CatKeys();
    const { key, id } = provider.add('shelter');
    const result = await provider.authenticate(bearer(key));
    expect(result).toEqual({ user: { id: 'shelter' }, session: { method: 'api-key', keyId: id } });
    expect(result).not.toHaveProperty('mfa');
    expect(provider.lookups).toEqual([id]);
  });

  it('refuses a wrong secret, an unknown id and a revoked key alike: 401 invalid_token, same message', async () => {
    const provider = new CatKeys({ realm: 'store' });
    const { key, id } = provider.add('shelter');
    const other = provider.generate().key;

    const wrongSecret = `${key.slice(0, -43)}${other.slice(-43)}`;
    const unknownId = `cat_${'0'.repeat(16)}_${key.slice(-43)}`;
    for (const token of [wrongSecret, unknownId]) {
      const error = await rejection(provider.authenticate(bearer(token)));
      expect(error).toMatchObject({ status: 401, message: 'invalid api key', challenge: challenge('invalid api key', 'store') });
    }

    provider.rows.delete(id); // revoked: the lookup finds nothing
    expect((await rejection(provider.authenticate(bearer(key)))).message).toBe('invalid api key');
  });

  it('refuses a key whose user is gone', async () => {
    const provider = new CatKeys();
    const { key, id } = provider.add('shelter');
    provider.rows.set(id, { ...provider.rows.get(id)!, user: null as never });
    expect((await rejection(provider.authenticate(bearer(key)))).message).toBe('invalid api key');
  });

  it('refuses a key from its expiresAt on, and only when the secret matched', async () => {
    const provider = new CatKeys();
    const expired = provider.add('shelter', new Date(NOW));
    const valid = provider.add('shelter', new Date(NOW + 1));
    const forever = provider.add('shelter', null);

    const error = await rejection(provider.authenticate(bearer(expired.key)));
    expect(error).toMatchObject({ message: 'api key expired', challenge: challenge('api key expired') });
    await expect(provider.authenticate(bearer(valid.key))).resolves.toEqual({
      user: { id: 'shelter' },
      session: { method: 'api-key', keyId: valid.id, expiresAt: new Date(NOW + 1) },
    });
    await expect(provider.authenticate(bearer(forever.key))).resolves.toMatchObject({ session: { method: 'api-key', keyId: forever.id } });

    // Someone without the secret learns nothing about the key, its expiry included.
    const guess = `${expired.key.slice(0, -43)}${provider.generate().key.slice(-43)}`;
    expect((await rejection(provider.authenticate(bearer(guess)))).message).toBe('invalid api key');
  });

  it('refuses a malformed key with its prefix before any lookup', async () => {
    const provider = new CatKeys();
    const { key } = provider.generate();
    const malformed = [
      'cat_',
      'cat_abc',
      key.slice(0, -1), // a secret one character short
      `${key}A`,
      `cat_ABCDEF0123456789_${key.slice(-43)}`, // an id in upper case
      `cat_${key.slice(4, 20)}_${'+'.repeat(43)}`,
    ];
    for (const token of malformed) {
      const error = await rejection(provider.authenticate(bearer(token)));
      expect(error).toMatchObject({ message: 'malformed api key', challenge: challenge('malformed api key') });
    }
    expect(provider.lookups).toEqual([]);
  });

  it('leaves other credentials to the other providers: no header, other schemes, other prefixes, JWTs', async () => {
    const provider = new CatKeys();
    const { key } = provider.add('shelter');
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl';
    for (const context of [
      http({}),
      http({ authorization: `Basic ${Buffer.from('cat:secret').toString('base64')}` }),
      http({ authorization: `Token ${key}` }),
      http({ 'x-api-key': key }),
      bearer(`dog_${key.slice(4)}`),
      bearer(`catalog_${key.slice(4)}`),
      bearer(jwt),
    ]) {
      await expect(provider.authenticate(context)).resolves.toBeNull();
    }
    expect(provider.lookups).toEqual([]);
  });

  it('answers a Bearer header without exactly one token as JwtBearerProvider does', async () => {
    const provider = new CatKeys();
    for (const authorization of ['Bearer', 'Bearer   ', 'Bearer cat_a cat_b']) {
      const error = await rejection(provider.authenticate(http({ authorization })));
      expect(error.challenge).toBe(challenge('malformed authorization header'));
    }
    expect(provider.challenge()).toBe('Bearer realm="api"');
  });

  it('does the same hashing and one constant-time comparison whether or not the id exists', async () => {
    const provider = new CatKeys();
    const { key } = provider.add('shelter');
    const unknown = provider.generate().key;
    const wrongSecret = `${key.slice(0, -43)}${unknown.slice(-43)}`;

    const cost = async (token: string) => {
      crypto.hashes = 0;
      crypto.comparisons = 0;
      await provider.authenticate(bearer(token)).catch(() => undefined);
      return { hashes: crypto.hashes, comparisons: crypto.comparisons };
    };
    const valid = await cost(key);
    expect(valid).toEqual({ hashes: 1, comparisons: 1 });
    expect(await cost(wrongSecret)).toEqual(valid);
    expect(await cost(unknown)).toEqual(valid);
  });
});

describe('ApiKeyProvider: transports', () => {
  it('reads the key from a WebSocket handshake: its Authorization header, or socket.io auth.token', async () => {
    const provider = new CatKeys();
    const { key, id } = provider.add('shelter');
    const session = { method: 'api-key', keyId: id };
    await expect(provider.authenticate(contextOf('ws', { handshake: { headers: { authorization: `Bearer ${key}` } } }))).resolves.toEqual({
      user: { id: 'shelter' },
      session,
    });
    await expect(provider.authenticate(contextOf('ws', { request: { headers: { authorization: `Bearer ${key}` } } }))).resolves.toEqual({
      user: { id: 'shelter' },
      session,
    });
    await expect(provider.authenticate(contextOf('ws', { handshake: { headers: {}, auth: { token: key } } }))).resolves.toEqual({
      user: { id: 'shelter' },
      session,
    });
  });

  it('finds nothing over RPC, whose metadata is transport specific', async () => {
    const provider = new CatKeys();
    const { key } = provider.add('shelter');
    await expect(provider.authenticate(contextOf('rpc', { authorization: `Bearer ${key}`, key }))).resolves.toBeNull();
  });
});

describe('JwtBearerProvider next to API keys', () => {
  class Bearer extends JwtBearerProvider<User> {
    readonly seen: JwtClaims[] = [];
    constructor() {
      super({ key: 'test-secret-that-is-at-least-32-bytes-long!' });
    }
    validate(claims: JwtClaims) {
      this.seen.push(claims);
      return { id: claims.sub! };
    }
  }

  it('leaves a token shaped like an API key, of any prefix, to the next provider', async () => {
    const provider = new Bearer();
    for (const token of [new CatKeys().generate().key, `sk_${'a'.repeat(16)}_${'b'.repeat(43)}`]) {
      await expect(provider.authenticate(bearer(token))).resolves.toBeNull();
      await expect(provider.authenticate(contextOf('ws', { handshake: { headers: {}, auth: { token } } }))).resolves.toBeNull();
    }
    expect(provider.seen).toEqual([]);
  });

  it('still refuses other tokens that are no JWT, with an invalid_token challenge', async () => {
    const provider = new Bearer();
    for (const token of ['not-a-jwt', 'cat_abc', `cat_${'a'.repeat(16)}_short`]) {
      const error = await rejection(provider.authenticate(bearer(token)));
      expect(error).toMatchObject({ message: 'malformed token', challenge: challenge('malformed token') });
    }
  });
});
