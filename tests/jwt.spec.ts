import { createHmac, createSecretKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { JwksClient, JwtError, JwtSigner, JwtVerifier, type JwsAlgorithm } from '../lib/index.js';

const NOW = 1_800_000_000; // JWT times are in seconds
const nowMs = () => NOW * 1000; // clocks are epoch milliseconds
const SECRET = 'test-secret-that-is-at-least-32-bytes-long!';
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** Hand-rolled HS256 token, so malformed headers can be produced. */
function hs256(payload: object, header: object = { alg: 'HS256', typ: 'JWT' }, secret = SECRET) {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

async function rejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(JwtError);
    return (error as Error).message;
  }

  throw new Error('expected a rejection');
}

const keys = {
  rsa: generateKeyPairSync('rsa', { modulusLength: 2048 }),
  ec: generateKeyPairSync('ec', { namedCurve: 'P-256' }),
  ed: generateKeyPairSync('ed25519'),
};

describe('JwtVerifier: HS256', () => {
  const verifier = (options = {}) => new JwtVerifier({ key: SECRET, now: nowMs, ...options });

  it('accepts a valid token', async () => {
    await expect(verifier().verify(hs256({ sub: 'u1', exp: NOW + 10 }))).resolves.toEqual({ sub: 'u1', exp: NOW + 10 });
  });

  it('refuses secrets shorter than 32 bytes, and HS256 with a JWKS', () => {
    expect(() => new JwtVerifier({ key: 'short' })).toThrow(/32 bytes/);
    expect(() => new JwtVerifier({ jwks: 'https://idp/jwks', algorithms: ['HS256'] })).toThrow(/HS256/);
  });

  it.each([
    ['none', { alg: 'none' }],
    ['HS512', { alg: 'HS512' }],
    ['RS256 on an HMAC verifier', { alg: 'RS256' }],
  ])('rejects alg %s', async (_, header) => {
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, header)))).toBe('unsupported algorithm');
  });

  it('rejects bad signatures, crit headers and malformed input', async () => {
    const good = hs256({ sub: 'u1', exp: NOW + 10 });
    const [h, , s] = good.split('.');

    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, undefined, 'z'.repeat(32))))).toBe('invalid signature');
    expect(await rejection(verifier().verify(`${h}.${b64({ sub: 'admin', exp: NOW + 10 })}.${s}`))).toBe('invalid signature');
    expect(await rejection(verifier().verify(good.slice(0, -4)))).toBe('invalid signature');
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10 }, { alg: 'HS256', crit: ['x'] })))).toBe(
      'unsupported critical header',
    );

    for (const bad of ['a.b', 'a.b.c.d', `${h}.${b64({})}.`, '!!.e30.xx', `${b64([])}.e30.xx`]) {
      expect(await rejection(verifier().verify(bad))).toBe('malformed token');
    }
  });

  it('checks time claims with leeway, and requires exp by default', async () => {
    expect(await rejection(verifier().verify(hs256({ exp: NOW })))).toBe('token expired');
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10, nbf: NOW + 1 })))).toBe('token not yet valid');
    expect(await rejection(verifier().verify(hs256({ exp: NOW + 10, iat: NOW + 100 })))).toBe('token issued in the future');
    expect(await rejection(verifier().verify(hs256({ exp: String(NOW + 10) })))).toBe('invalid exp');
    expect(await rejection(verifier().verify(hs256({ sub: 'u1' })))).toBe('missing exp');

    await expect(verifier({ clockTolerance: '5s' }).verify(hs256({ exp: NOW - 2, nbf: NOW + 2 }))).resolves.toBeTruthy();
    expect(await rejection(verifier({ maxAge: '1m' }).verify(hs256({ exp: NOW + 10, iat: NOW - 61 })))).toBe('token too old');
  });

  it('checks iss, aud and typ', async () => {
    const v = verifier({ issuer: 'https://idp', audience: ['api', 'admin'], type: 'at+jwt' });
    const header = { alg: 'HS256', typ: 'at+jwt' };

    await expect(v.verify(hs256({ iss: 'https://idp', aud: ['x', 'admin'], exp: NOW + 1 }, header))).resolves.toBeTruthy();
    expect(await rejection(v.verify(hs256({ iss: 'https://evil', aud: 'api', exp: NOW + 1 }, header)))).toBe('unexpected issuer');
    expect(await rejection(v.verify(hs256({ iss: 'https://idp', aud: 'x', exp: NOW + 1 }, header)))).toBe('unexpected audience');
    expect(await rejection(v.verify(hs256({ iss: 'https://idp', aud: 'api', exp: NOW + 1 })))).toBe('unexpected token type');
  });
});

describe('JwtSigner + JwtVerifier: asymmetric', () => {
  const cases: [JwsAlgorithm, { privateKey: KeyObject; publicKey: KeyObject }][] = [
    ['RS256', keys.rsa],
    ['ES256', keys.ec],
    ['EdDSA', keys.ed],
  ];

  it.each(cases)('%s round-trips and derives the algorithm from the key', async (alg, pair) => {
    const token = new JwtSigner({ key: pair.privateKey, alg, now: nowMs, issuer: 'i' }).sign({ sub: 'u1' });
    const claims = await new JwtVerifier({ key: pair.publicKey, now: nowMs, issuer: 'i' }).verify(token);
    expect(claims).toMatchObject({ sub: 'u1', iat: NOW, exp: NOW + 900, iss: 'i' });
    expect(claims.jti).toEqual(expect.any(String));
  });

  it('binds algorithms to key types (no RSA/HMAC confusion, no curve confusion)', async () => {
    // Classic attack: HS256 token whose "secret" is the RSA public key PEM.
    const pem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' });
    const forged = hs256({ sub: 'admin', exp: NOW + 10 }, { alg: 'HS256' }, pem as string);
    expect(await rejection(new JwtVerifier({ key: keys.rsa.publicKey, now: nowMs }).verify(forged))).toBe(
      'unsupported algorithm',
    );

    // An algorithm the key cannot serve fails when the verifier is created, not at the first request.
    expect(() => new JwtVerifier({ key: keys.rsa.publicKey, algorithms: ['HS256'] })).toThrow(
      /JwtVerifier: the key is not a valid HS256 key/,
    );

    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    expect(() => new JwtSigner({ key: p384.privateKey, alg: 'ES256' })).toThrow(/not a valid ES256 key/);
    expect(() => new JwtSigner({ key: keys.ec.publicKey, alg: 'ES256' })).toThrow(/private key/);
    expect(() => new JwtSigner({ key: generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey, alg: 'RS256' })).toThrow();
    expect(() => new JwtSigner({ key: generateKeyPairSync('ed448').privateKey, alg: 'EdDSA' })).toThrow();
  });

  it('reads PEM text as the key it is, never as an HS256 secret', async () => {
    // jsonwebtoken users pass keys as PEM strings. Read as an HMAC secret, a
    // public key would let anyone who has it (everyone) sign tokens.
    const publicPem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const forged = hs256({ sub: 'admin', exp: NOW + 10 }, { alg: 'HS256' }, publicPem);
    for (const key of [publicPem, Buffer.from(publicPem)]) {
      expect(await rejection(new JwtVerifier({ key, now: nowMs }).verify(forged))).toBe('unsupported algorithm');
    }
    expect(() => new JwtVerifier({ key: publicPem, algorithms: ['HS256'] })).toThrow(/not a valid HS256 key/);

    // PEM keys work as keys: PKCS#1 and SEC1 private keys sign, SPKI keys verify.
    const header = (token: string) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
    const rsaPem = keys.rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
    const token = new JwtSigner({ key: rsaPem, now: nowMs }).sign({ sub: 'u1' });
    expect(header(token).alg).toBe('RS256');
    await expect(new JwtVerifier({ key: publicPem, now: nowMs }).verify(token)).resolves.toMatchObject({ sub: 'u1' });

    const ecPem = keys.ec.privateKey.export({ type: 'sec1', format: 'pem' }) as string;
    expect(header(new JwtSigner({ key: ecPem }).sign({})).alg).toBe('ES256');
    expect(() => new JwtSigner({ key: publicPem })).toThrow(/private key/);
  });

  it('rejects DER-encoded ES256 signatures (JWS needs raw r||s)', async () => {
    const token = new JwtSigner({ key: keys.ec.privateKey, alg: 'ES256', now: nowMs }).sign({});
    const [h, p] = token.split('.');
    const { sign } = await import('node:crypto');
    const der = sign('sha256', Buffer.from(`${h}.${p}`), keys.ec.privateKey).toString('base64url');

    expect(await rejection(new JwtVerifier({ key: keys.ec.publicKey, now: nowMs }).verify(`${h}.${p}.${der}`))).toBe(
      'invalid signature',
    );
  });

  it('accepts a KeyObject secret for HS256', async () => {
    const key = createSecretKey(Buffer.from(SECRET));
    const token = new JwtSigner({ key, alg: 'HS256', now: nowMs }).sign({ sub: 'u1' });
    await expect(new JwtVerifier({ key: SECRET, now: nowMs }).verify(token)).resolves.toMatchObject({ sub: 'u1' });
  });

  it('takes the algorithm from the key, and lifetimes as durations', async () => {
    const header = (token: string) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
    const ec = new JwtSigner({ key: keys.ec.privateKey, ttl: '1h', now: nowMs });
    expect(header(ec.sign({}))).toEqual({ alg: 'ES256', typ: 'JWT' });
    expect(header(new JwtSigner({ key: SECRET }).sign({})).alg).toBe('HS256');

    const verifier = new JwtVerifier({ key: keys.ec.publicKey, now: nowMs });
    await expect(verifier.verify(ec.sign({}))).resolves.toMatchObject({ iat: NOW, exp: NOW + 3600 });
    await expect(verifier.verify(ec.sign({}, { ttl: '2m' }))).resolves.toMatchObject({ exp: NOW + 120 });

    expect(() => new JwtSigner({ key: SECRET, ttl: '15 minutes' as never })).toThrow(/Invalid duration/);
    expect(() => new JwtVerifier({ key: SECRET, clockTolerance: -5 })).toThrow(/Invalid duration/);
  });
});

describe('JwksClient', () => {
  let server: Server;
  let uri: string;
  let published: object[];
  let status = 200;
  let requests = 0;

  const jwk = (key: KeyObject, kid: string, extra: object = {}) => ({ ...key.export({ format: 'jwk' }), kid, ...extra });

  beforeAll(async () => {
    server = createServer((_, res) => {
      requests++;
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ keys: published }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    uri = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks`;
  });
  afterAll(() => new Promise((resolve) => server.close(resolve)));
  beforeEach(() => {
    requests = 0;
    status = 200;
    published = [jwk(keys.rsa.publicKey, 'rsa-1', { alg: 'RS256', use: 'sig' }), jwk(keys.ec.publicKey, 'ec-1')];
  });

  // The identity provider, and the API the tokens are for.
  const idp = { issuer: 'https://idp.test', audience: 'my-api' };
  const sign = (alg: JwsAlgorithm, key: KeyObject, kid?: string, audience = idp.audience) =>
    new JwtSigner({ key, alg, kid, now: nowMs, issuer: idp.issuer, audience }).sign({ sub: 'u1' });

  it('verifies by kid, caches the set, and ignores encryption keys', async () => {
    published.push(jwk(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey, 'enc', { use: 'enc' }));
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });

    await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'));
    await verifier.verify(sign('ES256', keys.ec.privateKey, 'ec-1'));
    expect(requests).toBe(1);

    expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, 'enc')))).toBe('no matching key');
  });

  it('refetches on an unknown kid (rotation), at most once per cooldown', async () => {
    let clock = 0;
    const client = new JwksClient(uri, { cooldown: 30_000, now: () => clock });
    const verifier = new JwtVerifier({ jwks: client, ...idp, now: nowMs });
    await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1'));

    const rotated = generateKeyPairSync('rsa', { modulusLength: 2048 });
    published = [jwk(rotated.publicKey, 'rsa-2')];
    clock = 1_000; // within cooldown: the unknown kid does not trigger a fetch
    expect(await rejection(verifier.verify(sign('RS256', rotated.privateKey, 'rsa-2')))).toBe('no matching key');
    expect(requests).toBe(1);

    clock = 31_000;
    await expect(verifier.verify(sign('RS256', rotated.privateKey, 'rsa-2'))).resolves.toBeTruthy();
    expect(requests).toBe(2);

    // Old key is gone after rotation.
    clock = 62_000;
    expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')))).toBe('no matching key');
  });

  it('shares one request between concurrent refreshes', async () => {
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    const token = sign('RS256', keys.rsa.privateKey, 'rsa-1');
    await Promise.all(Array.from({ length: 10 }, () => verifier.verify(token)));
    expect(requests).toBe(1);
  });

  it('keeps serving cached keys when a refresh fails', async () => {
    let clock = 0;
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri, { cacheTtl: 1_000, now: () => clock }), ...idp, now: nowMs });
    const token = sign('RS256', keys.rsa.privateKey, 'rsa-1');
    await verifier.verify(token);

    status = 500;
    clock = 5_000;
    await expect(verifier.verify(token)).resolves.toBeTruthy();
  });

  it('refuses a JWK whose alg disagrees with the token, and kid-less tokens against ambiguous sets', async () => {
    published = [jwk(keys.rsa.publicKey, 'rsa-1', { alg: 'PS256' })];
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')))).toBe('no matching key');

    published = [jwk(keys.rsa.publicKey, 'a'), jwk(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey, 'b')];
    const ambiguous = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(ambiguous.verify(sign('RS256', keys.rsa.privateKey)))).toBe('no matching key');
  });

  it('needs an issuer and an audience: an identity provider signs tokens for all of its clients', async () => {
    expect(() => new JwtVerifier({ jwks: uri })).toThrow(
      'JwtVerifier: a `jwks` verifier needs `issuer` and `audience`.',
    );
    expect(() => new JwtVerifier({ jwks: uri, issuer: idp.issuer })).toThrow(/needs `issuer` and `audience`/);

    // A token the same provider issued to another application.
    const other = sign('RS256', keys.rsa.privateKey, 'rsa-1', 'another-app');
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });
    expect(await rejection(verifier.verify(other))).toBe('unexpected audience');

    // Tokens that carry no audience (AWS Cognito access tokens) take an explicit opt-out.
    const anyAudience = new JwtVerifier({ jwks: new JwksClient(uri), issuer: idp.issuer, audience: false, now: nowMs });
    await expect(anyAudience.verify(other)).resolves.toMatchObject({ aud: 'another-app' });
  });

  it('reports an unreachable key set as an outage, not as a bad token', async () => {
    status = 503;
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs });

    const error = await verifier.verify(sign('RS256', keys.rsa.privateKey, 'rsa-1')).catch((e: Error) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(JwtError); // JwtBearerProvider answers JwtErrors with a 401
    expect((error as Error).message).toBe(`JWKS ${uri} is unavailable: it answered 503`);
  });

  it('retries a key set that failed to load at most once per cooldown', async () => {
    let clock = 0;
    status = 503;
    const verifier = new JwtVerifier({ jwks: new JwksClient(uri, { cooldown: 30_000, now: () => clock }), ...idp, now: nowMs });
    const token = sign('RS256', keys.rsa.privateKey, 'rsa-1');

    await expect(verifier.verify(token)).rejects.toThrow(/is unavailable/);
    clock = 10_000;
    await expect(verifier.verify(token)).rejects.toThrow(/is unavailable/);
    expect(requests).toBe(1); // the provider is down: no request per incoming token

    status = 200;
    clock = 31_000;
    await expect(verifier.verify(token)).resolves.toMatchObject({ sub: 'u1' });
    expect(requests).toBe(2);
  });

  it('verifies EdDSA only when enabled', async () => {
    published = [jwk(keys.ed.publicKey, 'ed-1')];
    const token = sign('EdDSA', keys.ed.privateKey, 'ed-1');

    expect(await rejection(new JwtVerifier({ jwks: new JwksClient(uri), ...idp, now: nowMs }).verify(token))).toBe(
      'unsupported algorithm',
    );

    const withEd = new JwtVerifier({ jwks: new JwksClient(uri), algorithms: ['EdDSA'], ...idp, now: nowMs });
    await expect(withEd.verify(token)).resolves.toBeTruthy();
  });
});
