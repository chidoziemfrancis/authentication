/**
 * OpenID Connect sign-in with the defaults a production app keeps (a `Secure` transaction
 * cookie), on Express and Fastify, against the mock identity provider: what the browser gets
 * on the login and callback responses (`Cache-Control: no-store`, `__Host-oidc_tx` for
 * `oidc.transactionTtl`), and each way the client authenticates at the token endpoint
 * (`client_secret_basic`, `client_secret_post`, a public client with `none`).
 */
import { Controller, Get, Injectable, Module, Param, Query, Redirect, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  OidcAccountResolver,
  OidcService,
  Public,
  SessionCookieProvider,
  type OidcProfile,
  type SessionRecord,
} from '../lib/index.js';
import { MockOidcProvider } from './mock-oidc.js';

const idp = new MockOidcProvider();

@Injectable()
class Identities extends OidcAccountResolver {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerHandler('oidc', this);
  }
  resolveUser(profile: OidcProfile) {
    return { id: `${profile.provider}:${profile.subject}` };
  }
}

@Injectable()
class SessionAuth extends SessionCookieProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(session: SessionRecord) {
    return { id: session.userId };
  }
}

@Public()
@Controller('auth/oidc')
class OidcController {
  constructor(private readonly oidcService: OidcService) {}

  @Get(':provider/login')
  @Redirect()
  login(@Param('provider') provider: string, @Query('redirectTo') redirectTo?: string) {
    return this.oidcService.start(provider, { redirectTo });
  }

  @Get(':provider/callback')
  @Redirect()
  callback(@Param('provider') provider: string, @Query() query: Record<string, string>) {
    return this.oidcService.finish(provider, query);
  }
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
          oidc: {
            callbackUrl: 'https://app.test/auth/oidc/:provider/callback',
            transactionTtl: '5m',
            providers: {
              basic: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret },
              post: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret, tokenEndpointAuthMethod: 'client_secret_post' },
              spa: { issuer: idp.issuer, clientId: idp.publicClientId, tokenEndpointAuthMethod: 'none' },
            },
          },
        }),
      }),
    ],
    controllers: [OidcController, MeController],
    providers: [Identities, SessionAuth],
  })
  class OidcAppModule {}
  return OidcAppModule;
}

const setCookies = (res: request.Response) => ([] as string[]).concat(res.headers['set-cookie'] ?? []);
const cookieNamed = (res: request.Response, name: string) => setCookies(res).find((c) => c.startsWith(`${name}=`));
const attributesOf = (setCookie: string) =>
  setCookie
    .split(';')
    .slice(1)
    .map((part) => part.trim().toLowerCase())
    .sort();

beforeAll(() => idp.start());
afterAll(() => idp.stop());

describe.each(adapters.map((a) => a.name))('OpenID Connect with production cookies (%s)', (adapter) => {
  let app: INestApplication;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    app = await createApp(adapter, appModule());
  });
  afterAll(() => app.close());

  async function signIn(provider: string, sub: string) {
    const started = await http().get(`/auth/oidc/${provider}/login`).query({ redirectTo: '/orders' }).expect(302);
    const location = started.headers.location as string;
    const tx = cookieNamed(started, '__Host-oidc_tx')!;
    const code = idp.approve(location, { sub });
    const finished = await http()
      .get(`/auth/oidc/${provider}/callback`)
      .query({ code, state: new URL(location).searchParams.get('state')! })
      .set('Cookie', tx.split(';')[0])
      .expect(302);
    return { started, finished, location };
  }

  it('keeps the login and the callback out of caches, with a __Host- transaction cookie for transactionTtl', async () => {
    const { started, finished } = await signIn('basic', 'alice');

    expect(started.headers['cache-control']).toBe('no-store');
    expect(attributesOf(cookieNamed(started, '__Host-oidc_tx')!)).toEqual(['httponly', 'max-age=300', 'path=/', 'samesite=lax', 'secure']);

    expect(finished.headers['cache-control']).toBe('no-store');
    expect(finished.headers.location).toBe('/orders');
    expect(cookieNamed(finished, '__Host-oidc_tx')).toMatch(/^__Host-oidc_tx=;.*Max-Age=0/i);
    const session = cookieNamed(finished, '__Host-sid')!;
    await http().get('/me').set('Cookie', session.split(';')[0]).expect(200, { id: 'basic:alice' });
  });

  it.each([
    ['basic', 'client_secret_basic'],
    ['post', 'client_secret_post'],
    ['spa', 'none'],
  ])('authenticates the %s client with %s at the token endpoint', async (provider, method) => {
    const before = idp.clientAuthentications.length;
    const { finished, location } = await signIn(provider, `${provider}-user`);

    expect(idp.clientAuthentications.slice(before)).toEqual([method]);
    expect(new URL(location).searchParams.get('code_challenge_method')).toBe('S256');
    await http()
      .get('/me')
      .set('Cookie', cookieNamed(finished, '__Host-sid')!.split(';')[0])
      .expect(200, { id: `${provider}:${provider}-user` });
  });
});
