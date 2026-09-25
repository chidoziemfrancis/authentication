/**
 * A `JwtBearerProvider` for tokens from another issuer (`super({ jwks, issuer, audience })`),
 * in an app on Express and Fastify, against an identity provider's key set served on
 * loopback: what API clients see (200, the RFC 6750 challenge, a 500 for an outage) and what
 * the identity provider sees (how often its key set is fetched).
 */
import { createHmac, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Controller, Get, Inject, Injectable, Logger, Module, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentSession,
  CurrentUser,
  JwksClient,
  JwtBearerProvider,
  JwtSigner,
  type JwtClaims,
} from '../lib/index.js';

const ISSUER = 'https://login.partner.test';
const AUDIENCE = 'orders-api';
const JWKS = Symbol('JWKS');

/** The identity provider's key set endpoint. */
class KeySet {
  keys: { kid: string; privateKey: KeyObject; publicKey: KeyObject }[] = [];
  status = 200;
  requests = 0;
  url = '';
  private server?: Server;

  async start() {
    this.server = createServer((_, res) => {
      this.requests++;
      const keys = this.keys.map(({ kid, publicKey }) => ({ ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }));
      res.writeHead(this.status, { 'content-type': 'application/json' }).end(JSON.stringify({ keys }));
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}/.well-known/jwks.json`;
  }

  stop() {
    return new Promise((resolve) => this.server?.close(resolve));
  }

  rotate() {
    const key = { kid: `k${this.keys.length + 1}`, ...generateKeyPairSync('rsa', { modulusLength: 2048 }) };
    this.keys.push(key);
    return key;
  }

  token(claims: JwtClaims = {}, { key = this.keys[0], audience = AUDIENCE, type = 'at+jwt' } = {}) {
    return new JwtSigner({ key: key.privateKey, kid: key.kid, issuer: ISSUER, audience, type, ttl: '5m' }).sign({ sub: 'partner-7', ...claims });
  }
}

const keySet = new KeySet();
let clock = 0;

@Injectable()
class PartnerAuth extends JwtBearerProvider<{ id: string }> {
  constructor(@Inject(JWKS) jwks: JwksClient, registry: AuthenticationRegistry) {
    super({ jwks, issuer: ISSUER, audience: AUDIENCE, type: 'at+jwt', realm: 'partner' });
    registry.registerProvider(this);
  }
  validate(claims: JwtClaims) {
    return claims.sub === 'revoked-partner' ? null : { id: claims.sub! };
  }
}

@Controller('orders')
class OrdersController {
  @Get()
  list(@CurrentUser('id') id: string, @CurrentSession() claims: JwtClaims) {
    return { id, iss: claims.iss, scope: claims.scope ?? null };
  }
}

@Module({
  imports: [AuthenticationModule.forRoot()],
  controllers: [OrdersController],
  providers: [
    { provide: JWKS, useFactory: () => new JwksClient(keySet.url, { cacheTtl: '10m', cooldown: '30s', now: () => clock }) },
    PartnerAuth,
  ],
})
class PartnerApiModule {}

beforeAll(() => keySet.start());
afterAll(() => keySet.stop());

describe.each(adapters.map((a) => a.name))('bearer tokens from another issuer, verified through its JWKS (%s)', (adapter) => {
  let app: INestApplication;
  const orders = (token: string) => request(app.getHttpServer()).get('/orders').set('Authorization', `Bearer ${token}`);

  beforeEach(async () => {
    clock = 0;
    keySet.keys = [];
    keySet.rotate();
    keySet.status = 200;
    keySet.requests = 0;
    app = await createApp(adapter, PartnerApiModule);
  });
  afterEach(() => app.close());

  it('accepts the issuer’s tokens, fetching its key set once for many requests', async () => {
    const token = keySet.token({ scope: 'orders:read' });

    await Promise.all(Array.from({ length: 5 }, () => orders(token).expect(200, { id: 'partner-7', iss: ISSUER, scope: 'orders:read' })));
    await orders(token).expect(200);

    expect(keySet.requests).toBe(1);
  });

  it('answers tokens issued to another application, of another type, or for a user validate() refuses, with the RFC 6750 challenge', async () => {
    const otherApp = await orders(keySet.token({}, { audience: 'billing-api' })).expect(401);
    expect(otherApp.headers['www-authenticate']).toBe('Bearer realm="partner", error="invalid_token", error_description="unexpected audience"');
    expect(otherApp.body).toEqual({ message: 'unexpected audience', error: 'Unauthorized', statusCode: 401 });

    const idToken = await orders(keySet.token({}, { type: 'JWT' })).expect(401);
    expect(idToken.headers['www-authenticate']).toMatch(/^Bearer realm="partner", error="invalid_token", error_description="[^"]*typ[^"]*"$/);

    const refused = await orders(keySet.token({ sub: 'revoked-partner' })).expect(401);
    expect(refused.headers['www-authenticate']).toMatch(/^Bearer realm="partner", error="invalid_token"/);

    const missing = await request(app.getHttpServer()).get('/orders').expect(401);
    expect(missing.headers['www-authenticate']).toBe('Bearer realm="partner"');
  });

  it('never takes the published public key as an HMAC secret (algorithm confusion)', async () => {
    const pem = keySet.keys[0].publicKey.export({ format: 'pem', type: 'spki' });
    const now = Math.floor(Date.now() / 1000);
    const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${encode({ alg: 'HS256', kid: 'k1', typ: 'at+jwt' })}.${encode({ iss: ISSUER, aud: AUDIENCE, sub: 'attacker', iat: now, exp: now + 300 })}`;
    const forged = `${unsigned}.${createHmac('sha256', pem).update(unsigned).digest('base64url')}`;

    const res = await orders(forged).expect(401);
    expect(res.headers['www-authenticate']).toMatch(/error="invalid_token"/);
  });

  it('follows a key rotation, refetching for an unknown kid at most once per cooldown', async () => {
    await orders(keySet.token()).expect(200);
    const rotated = keySet.rotate();

    // Within the cooldown of the first fetch, the new kid is unknown.
    clock = 1_000;
    await orders(keySet.token({}, { key: rotated })).expect(401);
    expect(keySet.requests).toBe(1);

    clock = 31_000;
    await orders(keySet.token({}, { key: rotated })).expect(200);
    await orders(keySet.token()).expect(200);
    expect(keySet.requests).toBe(2);

    // Random kids never make the API hammer the identity provider.
    const unknown = { ...rotated, kid: 'made-up' };
    clock = 32_000;
    await orders(keySet.token({}, { key: unknown })).expect(401);
    await orders(keySet.token({}, { key: unknown })).expect(401);
    expect(keySet.requests).toBe(2);

    clock = 62_000;
    await orders(keySet.token({}, { key: unknown })).expect(401);
    expect(keySet.requests).toBe(3);
  });

  it('answers 500, not 401, while the key set cannot be loaded, and recovers once it can', async () => {
    const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    keySet.status = 503;
    const token = keySet.token();

    const outage = await orders(token).expect(500);
    expect(outage.headers['www-authenticate']).toBeUndefined();
    expect(outage.body).toEqual({ message: 'Internal server error', statusCode: 500 });
    expect(String(logged.mock.calls[0]?.[0])).toContain(`JWKS ${keySet.url} is unavailable`);
    logged.mockRestore();

    keySet.status = 200;
    clock = 31_000;
    await orders(token).expect(200);
  });

  it('keeps serving the cached key set when a refresh fails', async () => {
    const token = keySet.token();
    await orders(token).expect(200);

    keySet.status = 503;
    clock = 11 * 60_000; // past cacheTtl
    await orders(token).expect(200);
    expect(keySet.requests).toBe(2);
  });
});
