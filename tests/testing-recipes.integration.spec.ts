/**
 * The README's "Testing an app" recipes, applied to an app as it ships (the production scrypt
 * cost, a mailer that talks to SMTP), on Express and Fastify: a cheaper `PasswordHasher`
 * through `overrideProvider()`, test users signed in without the password flow, a fake
 * handler registered between `compile()` and `init()` (or swapped with `replace`),
 * `AuthenticationContext.run()` for services, and the active store for assertions.
 */
import { Body, Controller, Get, HttpCode, Injectable, Module, Post, type INestApplication } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationContext,
  AuthenticationError,
  AuthenticationModule,
  AuthenticationRegistry,
  AuthenticationStorage,
  CurrentUser,
  JwtBearerProvider,
  MfaService,
  PasswordHasher,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SessionCookieProvider,
  SessionService,
  SignInService,
  TokenService,
  type JwtClaims,
  type PasswordResetLink,
  type SessionRecord,
} from '../lib/index.js';

const TOTP_KEY = 'testing-recipes-totp-key-of-32-characters';

/** Stands for a real SMTP client: nothing in a test may reach it. */
@Injectable()
class SmtpClient {
  readonly sent: string[] = [];
  send(to: string) {
    this.sent.push(to);
  }
}

@Injectable()
class UsersRepository {
  readonly hashes = new Map<string, string>();

  constructor(private readonly passwordHasher: PasswordHasher) {}

  async register(id: string, password: string) {
    this.hashes.set(id, await this.passwordHasher.hash(password));
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

@Injectable()
class JwtAuth extends JwtBearerProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this, { order: 1 });
  }
  validate(claims: JwtClaims) {
    return { id: claims.sub! };
  }
}

@Injectable()
class PasswordResetMailer extends PasswordResetHandler {
  constructor(
    private readonly smtpClient: SmtpClient,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerHandler('passwordReset', this);
  }
  findUser(email: string) {
    return { id: email.split('@')[0], passwordHash: null };
  }
  send(link: PasswordResetLink) {
    this.smtpClient.send(link.email);
  }
  updatePassword() {}
}

@Injectable()
class OrdersService {
  constructor(private readonly authenticationContext: AuthenticationContext) {}

  place(item: string) {
    return { item, by: this.authenticationContext.requireUser().id };
  }
}

@Controller()
class AppController {
  constructor(
    private readonly ordersService: OrdersService,
    private readonly passwordResetService: PasswordResetService,
    private readonly mfaService: MfaService,
  ) {}

  @Get('me')
  me(@CurrentUser('id') id: string) {
    return { id };
  }

  @Post('orders')
  order(@Body('item') item: string) {
    return this.ordersService.place(item);
  }

  @Post('mfa/enroll')
  enroll(@CurrentUser('id') id: string) {
    return this.mfaService.enroll(id, `${id}@example.com`);
  }

  @Public()
  @Post('password/forgot')
  @HttpCode(202)
  forgot(@Body('email') email: string) {
    this.passwordResetService.request(email);
  }
}

/** The app as it ships: the default scrypt cost (N=2^17), mail over SMTP. */
@Module({
  imports: [
    AuthenticationModule.forRoot({
      accessToken: { key: 'testing-recipes-secret-of-at-least-32-bytes' },
      mfa: { encryption: { keys: [TOTP_KEY] } },
      passwordReset: { url: 'https://example.com/reset-password' },
    }),
  ],
  controllers: [AppController],
  providers: [SmtpClient, UsersRepository, SessionAuth, JwtAuth, PasswordResetMailer, OrdersService],
})
class AppModule {}

describe.each(adapters.map((a) => a.name))('testing an app, the README’s way (%s)', (adapter) => {
  let app: INestApplication;
  const fakeMailer = { sent: [] as PasswordResetLink[] };
  const fake = Object.assign(Object.create(PasswordResetHandler.prototype) as PasswordResetHandler, {
    findUser: (email: string) => ({ id: email.split('@')[0], passwordHash: null }),
    send: (link: PasswordResetLink) => void fakeMailer.sent.push(link),
    updatePassword: () => {},
  });
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    app = await createApp(adapter, AppModule, {
      override: (builder) =>
        builder
          .overrideProvider(PasswordHasher)
          .useValue(new PasswordHasher({ logN: 10 }))
          .overrideProvider(PasswordResetMailer)
          .useValue(fake),
      // A plain instance doesn't register: register it between compile() and init().
      setup: (created) => created.get(AuthenticationRegistry).registerHandler('passwordReset', fake),
    });
  });
  afterAll(() => app.close());

  it('hashes with the cheaper PasswordHasher everywhere the app injects it', async () => {
    const users = app.get(UsersRepository);
    await users.register('ada', 'correct horse battery staple');

    expect(users.hashes.get('ada')).toMatch(/^\$scrypt\$ln=10,r=8,p=1\$/);
    expect(await app.get(PasswordHasher).verify('correct horse battery staple', users.hashes.get('ada'))).toBe(true);
  });

  it('signs test users in without the password flow: a session cookie, a bearer token, or signIn() outside a request', async () => {
    const { cookie } = await app.get(SessionService).create('ada');
    await http().get('/me').set('Cookie', cookie.split(';')[0]).expect(200, { id: 'ada' });

    const { accessToken } = await app.get(TokenService).issue('grace');
    await http().get('/me').set('Authorization', `Bearer ${accessToken}`).expect(200, { id: 'grace' });

    const signedIn = await app.get(SignInService).signIn('linus', { method: 'test' });
    await http().get('/me').set('Cookie', signedIn.cookie.split(';')[0]).expect(200, { id: 'linus' });
  });

  it('delivers links to the fake handler, and nothing to the real mailer’s SMTP client', async () => {
    await http().post('/password/forgot').send({ email: 'ada@example.com' }).expect(202);

    await vi.waitFor(() => expect(fakeMailer.sent).toEqual([expect.objectContaining({ email: 'ada@example.com' })]));
    expect(app.get(SmtpClient).sent).toEqual([]);
  });

  it('runs a service as a user with AuthenticationContext.run(), and refuses it outside one', () => {
    const ordersService = app.get(OrdersService);

    expect(app.get(AuthenticationContext).run({ user: { id: 'ada' } }, () => ordersService.place('cat-tree'))).toEqual({ item: 'cat-tree', by: 'ada' });
    expect(() => ordersService.place('cat-tree')).toThrow(AuthenticationError);
  });

  it('asserts on the active store: an enrolled secret is stored encrypted', async () => {
    const { cookie } = await app.get(SessionService).create('mfa-user');
    const { secret } = (await http().post('/mfa/enroll').set('Cookie', cookie.split(';')[0]).expect(201)).body;

    const stored = await app.get(AuthenticationStorage).mfa.getTotp('mfa-user');
    expect(stored).toMatchObject({ confirmed: false });
    expect(stored!.secret).not.toContain(secret);
  });
});

describe('fake handlers', () => {
  let moduleRef: TestingModule | undefined;
  afterEach(async () => {
    await moduleRef?.close();
    moduleRef = undefined;
  });

  it('an overridden handler that is never registered leaves the feature half-configured: startup fails, naming it', async () => {
    const halfConfigured = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PasswordResetMailer)
      .useValue({ findUser: () => null, send: () => {}, updatePassword: () => {} })
      .compile();

    await expect(halfConfigured.init()).rejects.toThrow(/`passwordReset` is configured, but no PasswordResetHandler is registered/);
  });

  it('`replace: true` swaps a handler that registered itself', async () => {
    const sent: PasswordResetLink[] = [];
    moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    const registry = moduleRef.get(AuthenticationRegistry);
    const replacement = Object.assign(Object.create(PasswordResetHandler.prototype) as PasswordResetHandler, {
      findUser: (email: string) => ({ id: email, passwordHash: null }),
      send: (link: PasswordResetLink) => void sent.push(link),
      updatePassword: () => {},
    });

    expect(() => registry.registerHandler('passwordReset', replacement)).toThrow(/PasswordResetMailer/);
    registry.registerHandler('passwordReset', replacement, { replace: true });
    await moduleRef.init();

    moduleRef.get(PasswordResetService).request('ada@example.com');
    await vi.waitFor(() => expect(sent).toHaveLength(1));
    expect(moduleRef.get(SmtpClient).sent).toEqual([]);
  });
});
