import { generateKeyPairSync } from 'node:crypto';
import { Controller, Get, Injectable, Module, Param, Query, Redirect, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationEvents,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  InMemoryOidcStateStore,
  MfaService,
  OidcAccountResolver,
  OidcService,
  Public,
  SessionService,
  SignInService,
  TokenService,
  github,
  microsoft,
  type AuthenticationEvent,
  type OidcOptions,
  type OidcProfile,
  type OidcResolveContext,
} from '../lib/index.js';
import { SessionAuthModule, UsersModule, UsersRepository, registryWith, storageWith, type User } from './fixtures.js';
import { MockOidcProvider } from './mock-oidc.js';

const idp = new MockOidcProvider();
const linked: OidcProfile[] = [];
const contexts: OidcResolveContext[] = [];

@Injectable()
class AccountResolver extends OidcAccountResolver {
  // (provider, subject) → user id, as a real app would keep in an accounts table.
  private readonly identities = new Map([
    ['mock:alice-sub', 'u1'],
    ['github:4242', 'u2'],
  ]);

  constructor(
    private readonly users: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('oidc', this);
  }
  resolveUser(profile: OidcProfile, _tokens: unknown, context: OidcResolveContext) {
    linked.push(profile);
    contexts.push(context);

    const key = `${profile.provider}:${profile.subject}`;
    const owner = this.identities.get(key);
    if (context.linkTo) {
      if (owner && owner !== context.linkTo.id) {
        return null; // someone else's identity
      }
      this.identities.set(key, context.linkTo.id);
      return this.users.findById(context.linkTo.id) ?? null;
    }

    return owner ? (this.users.findById(owner) ?? null) : null;
  }
}

/** The app's routes: login and callback, calling OidcService (the README's controller, at any path). */
function oidcController(path: string) {
  @Public()
  @Controller(path)
  class OidcController {
    constructor(private readonly oidc: OidcService) {}

    @Get(':provider/login')
    @Redirect()
    login(@Param('provider') provider: string, @Query('redirectTo') redirectTo?: string, @Query('link') link?: string) {
      return this.oidc.start(provider, { redirectTo, link: link === 'true' });
    }

    @Get(':provider/callback')
    @Redirect()
    callback(@Param('provider') provider: string, @Query() query: Record<string, string>) {
      return this.oidc.finish(provider, query);
    }
  }

  return OidcController;
}

@Controller('me')
class MeController {
  @Get()
  me(@CurrentUser('id') id: string) {
    return { id };
  }
}

function appModule() {
  @Module({
    imports: [
      AuthenticationModule.forRootAsync({
        useFactory: () => ({
          session: {
            cookie: { secure: false },
            // The same hook as every other sign-in: nothing OIDC-specific to configure.
            metadata: ({ headers }) => ({ userAgent: headers['user-agent'] ?? null }),
          },
          password: { logN: 10 },
          oidc: {
            callbackUrl: 'http://app.test/auth/oidc/:provider/callback',
            cookie: { secure: false },
            jwks: { cooldown: 0 },
            providers: {
              mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret },
              github: {
                ...github({ clientId: idp.clientId, clientSecret: idp.clientSecret }),
                authorizationEndpoint: `${idp.issuer}/gh/authorize`,
                tokenEndpoint: `${idp.issuer}/gh/token`,
                userinfoEndpoint: `${idp.issuer}/gh/user`,
              },
            },
          },
        }),
      }),
      UsersModule,
      SessionAuthModule,
    ],
    controllers: [MeController, oidcController('auth/oidc')],
    providers: [AccountResolver],
  })
  class OidcAppModule {}
  return OidcAppModule;
}

const cookies = (res: request.Response) => ([] as string[]).concat(res.headers['set-cookie'] ?? []);
const cookie = (res: request.Response, name: string) => cookies(res).find((c) => c.startsWith(`${name}=`))?.split(';')[0];

beforeAll(() => idp.start());
afterAll(() => idp.stop());

describe.each(adapters.map((a) => a.name))('OIDC sign-in (%s)', (adapter) => {
  let app: INestApplication;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    app = await createApp(adapter, appModule());
  });
  afterAll(() => app.close());

  async function begin(provider = 'mock', redirectTo?: string, { link, sid }: { link?: boolean; sid?: string } = {}) {
    let req = http()
      .get(`/auth/oidc/${provider}/login`)
      .query({ ...(redirectTo && { redirectTo }), ...(link && { link: 'true' }) });
    if (sid) {
      req = req.set('Cookie', sid);
    }

    const res = await req.expect(302);
    const location = res.headers.location as string;
    return { location, params: new URL(location).searchParams, tx: cookie(res, 'oidc_tx')! };
  }

  const callback = (provider: string, query: Record<string, string>, ...cookies: (string | undefined)[]) => {
    const req = http().get(`/auth/oidc/${provider}/callback`).query(query);
    const header = cookies.filter(Boolean).join('; ');
    return header ? req.set('Cookie', header) : req;
  };

  async function signInAs(sub: string) {
    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub });
    return cookie(await callback('mock', { code, state: params.get('state')! }, tx).expect(302), 'sid')!;
  }

  it('redirects to the IdP with PKCE (S256), state and nonce', async () => {
    const { location, params, tx } = await begin();

    expect(location.startsWith(`${idp.issuer}/authorize?`)).toBe(true);
    expect(Object.fromEntries(params)).toMatchObject({
      response_type: 'code',
      client_id: idp.clientId,
      redirect_uri: 'http://app.test/auth/oidc/mock/callback',
      scope: 'openid email profile',
      code_challenge_method: 'S256',
    });
    expect(params.get('code_challenge')).toMatch(/^[\w-]{43}$/);
    expect(params.get('nonce')).toMatch(/^[\w-]{43}$/);
    expect(tx).toBe(`oidc_tx=${params.get('state')}`);
  });

  it('completes the flow: session cookie, tx cookie cleared, safe redirect', async () => {
    const { location, params, tx } = await begin('mock', '/dashboard');
    const code = idp.approve(location, { sub: 'alice-sub' });
    const res = await callback('mock', { code, state: params.get('state')! }, tx).expect(302);

    expect(res.headers.location).toBe('/dashboard');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(cookies(res)).toContainEqual(expect.stringMatching(/^oidc_tx=; Max-Age=0;/));

    const sid = cookie(res, 'sid')!;
    await http().get('/me').set('Cookie', sid).expect(200, { id: 'u1' });

    expect(linked.at(-1)).toMatchObject({
      provider: 'mock',
      subject: 'alice-sub',
      email: 'alice-sub@idp.test',
      emailVerified: true,
      name: 'From Userinfo',
    });
  });

  it('verifies ES256 ID tokens too', async () => {
    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub', alg: 'ES256' });
    await callback('mock', { code, state: params.get('state')! }, tx).expect(302);
  });

  it('ignores open redirects', async () => {
    const { location, params, tx } = await begin('mock', '//evil.test/x');
    const code = idp.approve(location, { sub: 'alice-sub' });
    const res = await callback('mock', { code, state: params.get('state')! }, tx).expect(302);
    expect(res.headers.location).toBe('/');
  });

  describe('binding and replay', () => {
    it('rejects a callback without the browser’s transaction cookie (login CSRF)', async () => {
      const { location, params } = await begin();
      const code = idp.approve(location, { sub: 'alice-sub' });
      await callback('mock', { code, state: params.get('state')! }).expect(400);
    });

    it('rejects a state that belongs to another login', async () => {
      const first = await begin();
      const second = await begin();
      const code = idp.approve(first.location, { sub: 'alice-sub' });
      await callback('mock', { code, state: first.params.get('state')! }, second.tx).expect(400);
    });

    it('rejects a replayed callback', async () => {
      const { location, params, tx } = await begin();
      const code = idp.approve(location, { sub: 'alice-sub' });
      await callback('mock', { code, state: params.get('state')! }, tx).expect(302);
      await callback('mock', { code, state: params.get('state')! }, tx).expect(400);
    });

    it('rejects a transaction started for another provider', async () => {
      const { location, params, tx } = await begin('mock');
      const code = idp.approve(location, { sub: 'alice-sub' });
      await callback('github', { code, state: params.get('state')! }, tx).expect(400);
    });
  });

  describe('IdP responses that fail verification', () => {
    const attempt = async (
      status: number,
      options: Parameters<MockOidcProvider['approve']>[1],
      extra: Record<string, string> = {},
    ) => {
      const { location, params, tx } = await begin();
      const code = idp.approve(location, options);
      return callback('mock', { code, state: params.get('state')!, ...extra }, tx).expect(status);
    };

    it.each([
      ['nonce mismatch', { idToken: { nonce: 'other' } }, /nonce/],
      ['wrong audience', { idToken: { aud: 'someone-else' } }, /audience/],
      ['multiple audiences without azp', { idToken: { aud: ['nest-client', 'other'] } }, /azp/],
      ['expired', { idToken: { exp: Math.floor(Date.now() / 1000) - 120 } }, /expired/],
      ['wrong issuer', { idToken: { iss: 'https://evil.test' } }, /issuer/],
      ['foreign signing key', { signWith: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey }, /signature/],
      ['userinfo for another subject', { userinfoSub: 'mallory' }, /subject mismatch/],
      ['PKCE verifier mismatch', { codeChallenge: 'A'.repeat(43) }, /rejected the code/],
    ] as const)('%s → 401', async (_, options, message) => {
      const res = await attempt(401, { sub: 'alice-sub', ...options });
      expect(res.body.message).toMatch(message);
      expect(cookie(res, 'sid')).toBeUndefined();
    });

    it('rejects an `iss` response parameter from another issuer (RFC 9207) → 400', async () => {
      await attempt(400, { sub: 'alice-sub' }, { iss: 'https://evil.test' });
    });

    it('passes IdP errors through as 400', async () => {
      const { params, tx } = await begin();
      await callback('mock', { error: 'access_denied', state: params.get('state')! }, tx).expect(400);
    });

    it.each([
      ['token', 'token endpoint unavailable (503)'],
      ['userinfo', `userinfo endpoint unavailable (503)`],
    ] as const)('answers 502, not 401, when the %s endpoint is down', async (endpoint, message) => {
      const { location, params, tx } = await begin();
      const code = idp.approve(location, { sub: 'alice-sub' });

      idp.down = endpoint;
      try {
        const res = await callback('mock', { code, state: params.get('state')! }, tx).expect(502);
        expect(res.body).toEqual({ message, error: 'Bad Gateway', statusCode: 502 });
      } finally {
        idp.down = undefined;
      }
    });

    it('lets the resolver refuse an account → 403', async () => {
      await attempt(403, { sub: 'unknown-sub' });
    });
  });

  it('follows JWKS key rotation', async () => {
    idp.rotateRsaKey();
    const before = idp.jwksRequests;

    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub' });
    await callback('mock', { code, state: params.get('state')! }, tx).expect(302);

    expect(idp.jwksRequests).toBe(before + 1);
  });

  it('signs in with GitHub (OAuth 2.0), taking the primary verified email', async () => {
    const { location, params, tx } = await begin('github');

    expect(location.startsWith(`${idp.issuer}/gh/authorize?`)).toBe(true);
    expect(params.get('nonce')).toBeNull();
    expect(params.get('scope')).toBe('read:user user:email');

    const code = idp.approve(location, { sub: 'ignored' });
    const res = await callback('github', { code, state: params.get('state')! }, tx).expect(302);

    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u2' });
    expect(linked.at(-1)).toMatchObject({ provider: 'github', subject: '4242', email: 'octo@example.com', emailVerified: true, name: 'octocat' });
  });

  it('signs in through SignInService: `session.metadata`, the sign-in event, an empty resolver context', async () => {
    const events: AuthenticationEvent[] = [];
    const subscription = app.get(AuthenticationEvents).events$.subscribe((event) => events.push(event));

    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub' });
    await callback('mock', { code, state: params.get('state')! }, tx).set('User-Agent', 'Browser/1.0').expect(302);
    subscription.unsubscribe();

    expect(contexts.at(-1)).toEqual({});

    const sessions = await app.get(SessionService).list('u1');
    expect(sessions.at(-1)!.metadata).toEqual({ userAgent: 'Browser/1.0' });
    expect(events).toEqual([
      {
        type: 'sign-in',
        userId: 'u1',
        sessionId: sessions.at(-1)!.id,
        method: 'oidc:mock',
        metadata: { userAgent: 'Browser/1.0' },
      },
    ]);
  });

  it('replaces the browser’s previous session (fixation defence)', async () => {
    const before = await signInAs('alice-sub');

    const { location, params, tx } = await begin();
    const code = idp.approve(location, { sub: 'alice-sub' });
    const res = await callback('mock', { code, state: params.get('state')! }, tx, before).expect(302);

    await http().get('/me').set('Cookie', before).expect(401);
    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u1' });
  });

  describe('linking to the signed-in user (?link=true)', () => {
    it('links a new identity to the session’s user and keeps the session', async () => {
      const sid = await signInAs('alice-sub');

      const { location, params, tx } = await begin('mock', '/settings', { link: true, sid });
      const code = idp.approve(location, { sub: 'alice-second-account' });
      const res = await callback('mock', { code, state: params.get('state')! }, tx, sid).expect(302);

      expect(res.headers.location).toBe('/settings');
      expect(cookie(res, 'sid')).toBeUndefined(); // not a new sign-in
      expect(contexts.at(-1)).toEqual({ linkTo: { id: 'u1' } });
      await http().get('/me').set('Cookie', sid).expect(200, { id: 'u1' });

      // The linked identity now signs in to the same account.
      await http().get('/me').set('Cookie', await signInAs('alice-second-account')).expect(200, { id: 'u1' });
    });

    it('needs a signed-in session to start', async () => {
      await http().get('/auth/oidc/mock/login').query({ link: 'true' }).expect(401);
      await http().get('/auth/oidc/mock/login').query({ link: 'true' }).set('Cookie', `sid=${'x'.repeat(43)}`).expect(401);
    });

    it('refuses the callback when the session that started it is gone', async () => {
      const sid = await signInAs('alice-sub');
      const { location, params, tx } = await begin('mock', undefined, { link: true, sid });

      await app.get(SessionService).revokeAll('u1');

      const code = idp.approve(location, { sub: 'late-link-sub' });
      await callback('mock', { code, state: params.get('state')! }, tx, sid).expect(401);
      await callback('mock', { code, state: params.get('state')! }, tx).expect(400); // spent
    });

    it('refuses an identity that belongs to another user → 403', async () => {
      const sid = await signInAs('alice-sub');
      const { location, params, tx } = await begin('mock', undefined, { link: true, sid });
      const code = idp.approve(location, { sub: 'bob-sub-taken' });
      (app.get(AccountResolver) as any).identities.set('mock:bob-sub-taken', 'u2');

      await callback('mock', { code, state: params.get('state')! }, tx, sid).expect(403);
    });
  });

  it('answers 404 for unknown providers', async () => {
    await http().get('/auth/oidc/nope/login').expect(404);
    await http().get('/auth/oidc/__proto__/login').expect(404);
  });
});

describe.each(adapters.map((a) => a.name))('OIDC routes at another path, forRoot (%s)', (adapter) => {
  let app: INestApplication;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    @Injectable()
    class AnyoneIsAlice extends OidcAccountResolver {
      constructor(registry: AuthenticationRegistry) {
        super();
        registry.registerHandler('oidc', this);
      }
      resolveUser() {
        return { id: 'u1' };
      }
    }

    @Module({
      imports: [
        AuthenticationModule.forRoot({
          session: { cookie: { secure: false } },
          password: { logN: 10 },
          oidc: {
            callbackUrl: 'http://app.test/sso/:provider/callback',
            cookie: { secure: false },
            providers: { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } },
          },
        }),
        UsersModule,
        SessionAuthModule,
      ],
      controllers: [MeController, oidcController('sso')],
      providers: [AnyoneIsAlice],
    })
    class SsoModule {}

    app = await createApp(adapter, SsoModule);
  });
  afterAll(() => app.close());

  it('signs in through the routes the app declares, with the callbackUrl it configures', async () => {
    const login = await http().get('/sso/mock/login').expect(302);
    expect(login.headers['cache-control']).toBe('no-store');

    const params = new URL(login.headers.location).searchParams;
    expect(params.get('redirect_uri')).toBe('http://app.test/sso/mock/callback');

    const code = idp.approve(login.headers.location, { sub: 'anyone' });
    const res = await http()
      .get('/sso/mock/callback')
      .query({ code, state: params.get('state')! })
      .set('Cookie', cookie(login, 'oidc_tx')!)
      .expect(302);
    await http().get('/me').set('Cookie', cookie(res, 'sid')!).expect(200, { id: 'u1' });

    // The package mounts no routes of its own.
    await http().get('/auth/oidc/mock/login').expect(404);
  });
});

describe('OidcService', () => {
  const state = 'S'.repeat(43);
  function setup(oidc: Partial<OidcOptions> = {}) {
    const store = new InMemoryOidcStateStore();
    const storage = storageWith({ oidcStates: store });
    const sessions = new SessionService(storage, {});
    const signIn = new SignInService(sessions, new MfaService(storage, {}), new TokenService(storage, {}));

    const resolver = new (class extends OidcAccountResolver {
      resolveUser() {
        return { id: 'u1' };
      }
    })();

    const providers = { mock: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret } };
    const options = { oidc: { callbackUrl: 'https://app.test/auth/oidc/:provider/callback', providers, ...oidc } };
    const service = new OidcService(storage, registryWith(options, { oidc: resolver }), signIn, sessions, options);

    return { store, service };
  }

  it('names the transaction cookie __Host-oidc_tx when it is Secure, so no subdomain can plant one', async () => {
    const { cookies } = await setup().service.start('mock', { request: { method: 'GET', headers: {} } });
    expect(cookies).toEqual([expect.stringMatching(/^__Host-oidc_tx=[\w-]{43}; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/)]);
  });

  it('expires logins by the configured clock', async () => {
    let clock = Date.now();
    const { store, service } = setup({ now: () => clock });
    await store.saveOidcState({ state, provider: 'mock', codeVerifier: 'v', nonce: 'n', createdAt: new Date(clock), expiresAt: new Date(clock + 1_000) });

    clock += 2_000;

    const request = { method: 'GET', headers: { cookie: `__Host-oidc_tx=${state}` } };
    await expect(service.finish('mock', { state, code: 'c' }, { request })).rejects.toThrow('unknown or expired login');
  });

  it('checks oidc.callbackUrl at startup', () => {
    expect(() => setup({ callbackUrl: '/auth/oidc/:provider/callback' })).toThrow(
      "OidcService: `oidc.callbackUrl` must be the absolute URL of your callback route, with `:provider` where the provider's name goes",
    );
  });

  it('checks each provider’s credentials at startup; a public client says so', () => {
    const mock = { issuer: idp.issuer, clientId: idp.clientId };
    expect(() => setup({ providers: { mock } })).toThrow(
      "AuthenticationModule: `oidc.providers.mock.clientSecret` is required (the client secret the provider issued; a public " +
        "client sets `tokenEndpointAuthMethod: 'none'` instead), but it is undefined: is the environment variable it reads set?",
    );

    expect(() => setup({ providers: { mock: { ...mock, tokenEndpointAuthMethod: 'none' } } })).not.toThrow();

    expect(() => setup({ providers: { mock: { ...mock, clientId: '', clientSecret: 's' } } })).toThrow(
      '`oidc.providers.mock.clientId` is required (the client id the provider issued), but it is empty',
    );
  });

  it('throws when OpenID Connect is not enabled', async () => {
    const storage = storageWith();
    const sessions = new SessionService(storage, {});
    const signIn = new SignInService(sessions, new MfaService(storage, {}), new TokenService(storage, {}));
    const service = new OidcService(storage, registryWith(), signIn, sessions, {});

    await expect(service.start('mock')).rejects.toThrow(
      "OidcService: OpenID Connect is not enabled. Configure `oidc` in the AuthenticationModule options, and register an OidcAccountResolver: `registry.registerHandler('oidc', this)`.",
    );
  });
});

describe('presets', () => {
  it('refuses multi-tenant Microsoft endpoints', () => {
    expect(() => microsoft({ tenant: 'common', clientId: 'a', clientSecret: 'b' })).toThrow(/multi-tenant/);
    expect(microsoft({ tenant: 'contoso.onmicrosoft.com', clientId: 'a', clientSecret: 'b' }).issuer).toBe(
      'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0',
    );
  });
});

export type { User };
