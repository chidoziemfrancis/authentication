/**
 * The README's rate-limiting recipe with `@nestjs/throttler`, on Express and Fastify: a
 * root-module `APP_GUARD` tracking (email, IP) where the body names an account, `@Throttle()`
 * on the sign-in, magic-link and password-reset routes, and guessed credentials on protected
 * routes counted too, because the throttler runs before the authentication guard.
 */
import { Body, Controller, Get, HttpCode, Injectable, Module, Post, UnauthorizedException } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Throttle, ThrottlerGuard, ThrottlerModule, minutes } from '@nestjs/throttler';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  JwtBearerProvider,
  PasswordResetHandler,
  PasswordResetService,
  Public,
  SignInService,
  type JwtClaims,
  type PasswordResetLink,
} from '../lib/index.js';

const PASSWORD = 'correct horse battery staple';

/** Per IP everywhere; per (account, IP) where the body names an account. */
@Injectable()
class AuthThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    const ip = await super.getTracker(req);
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return email ? `${email}|${ip}` : ip;
  }
}

@Injectable()
class JwtAuth extends JwtBearerProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  validate(claims: JwtClaims) {
    return { id: claims.sub! };
  }
}

@Injectable()
class ResetMailer extends PasswordResetHandler {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerHandler('passwordReset', this);
  }
  findUser() {
    return null;
  }
  send(_link: PasswordResetLink) {}
  updatePassword() {}
}

@Controller()
class AuthController {
  constructor(
    private readonly signInService: SignInService,
    private readonly passwordResetService: PasswordResetService,
  ) {}

  @Public()
  @Throttle({ default: { limit: 5, ttl: minutes(15) } })
  @Post('auth/login')
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    if (body.password !== PASSWORD) {
      throw new UnauthorizedException('Invalid email or password');
    }
    await this.signInService.signIn(body.email.trim().toLowerCase(), { method: 'password' });
  }

  @Public()
  @Throttle({ default: { limit: 3, ttl: minutes(15) } })
  @Post('auth/password/forgot')
  @HttpCode(202)
  forgot(@Body('email') email: string) {
    this.passwordResetService.request(email);
  }

  @Get('orders')
  orders(@CurrentUser('id') id: string) {
    return { id };
  }
}

@Module({
  imports: [
    ThrottlerModule.forRoot([{ ttl: minutes(1), limit: 10 }]),
    AuthenticationModule.forRoot({
      accessToken: { key: 'throttler-test-secret-of-at-least-32-bytes' },
      passwordReset: { url: 'https://example.com/reset-password' },
    }),
  ],
  controllers: [AuthController],
  // In the root module, so it runs before the authentication guard.
  providers: [{ provide: APP_GUARD, useClass: AuthThrottlerGuard }, JwtAuth, ResetMailer],
})
class AppModule {}

describe.each(adapters.map((a) => a.name))('rate limiting with @nestjs/throttler (%s)', (adapter) => {
  let app: Awaited<ReturnType<typeof createApp>>;
  const http = () => request(app.getHttpServer());

  beforeEach(async () => {
    app = await createApp(adapter, AppModule);
  });
  afterEach(() => app.close());

  it('limits sign-in attempts per account and IP, the right password included, and leaves other accounts alone', async () => {
    for (let attempt = 0; attempt < 5; attempt++) {
      await http().post('/auth/login').send({ email: 'ada@example.com', password: 'guess' }).expect(401);
    }

    const limited = await http().post('/auth/login').send({ email: ' ADA@example.com ', password: PASSWORD }).expect(429);
    expect(limited.headers['retry-after']).toBeDefined();
    expect(limited.headers['set-cookie']).toBeUndefined();

    await http().post('/auth/login').send({ email: 'grace@example.com', password: PASSWORD }).expect(200);
  });

  it('limits password reset requests per address', async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      await http().post('/auth/password/forgot').send({ email: 'ada@example.com' }).expect(202);
    }

    await http().post('/auth/password/forgot').send({ email: 'ada@example.com' }).expect(429);
    await http().post('/auth/password/forgot').send({ email: 'grace@example.com' }).expect(202);
  });

  it('counts guessed bearer tokens on protected routes: the throttler answers before the authentication guard', async () => {
    for (let attempt = 0; attempt < 10; attempt++) {
      const res = await http().get('/orders').set('Authorization', `Bearer guess-${attempt}`).expect(401);
      expect(res.headers['www-authenticate']).toMatch(/^Bearer realm="api", error="invalid_token"/);
    }

    const limited = await http().get('/orders').set('Authorization', 'Bearer guess-10').expect(429);
    expect(limited.headers['www-authenticate']).toBeUndefined();
  });
});
