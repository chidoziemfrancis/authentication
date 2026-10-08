import { Controller, Get, Injectable, Logger, Module, Post, UseGuards, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AuthorizationModule, Can, Policy } from '@nestjs/authorization';
import { adapters, createApp } from './support/adapters.js';
import { Authenticate, AuthenticationGuard, AuthenticationModule, Public } from '../lib/index.js';
import { ApiKeyAuth, ApiKeyRepository, type User } from './fixtures.js';

@Policy()
class ArticlePolicy {
  viewAny(_user: User | null) {
    return true;
  }

  create(user: User | null) {
    return !!user?.roles.includes('editor');
  }
}

@Controller('articles')
class ArticlesController {
  @Get()
  @Public()
  @Can(ArticlePolicy, 'viewAny')
  list() {
    return [];
  }

  @Post()
  @Can(ArticlePolicy, 'create')
  create() {
    return { created: true };
  }

  // Authentication lets guests through; the policy decides.
  @Post('drafts')
  @Authenticate({ optional: true })
  @Can(ArticlePolicy, 'create')
  draft() {
    return { drafted: true };
  }
}

// `key-ci` is an editor; `key-viewer` is not.
class Keys extends ApiKeyRepository {
  override find(key: string) {
    if (key === 'key-viewer') {
      return { id: 'k2', user: { id: 'v1', email: 'v@example.com', name: 'V', roles: ['viewer'] } };
    }
    return super.find(key);
  }
}

/** The API keys, and the provider that authenticates them. */
@Module({ providers: [{ provide: ApiKeyRepository, useClass: Keys }, ApiKeyAuth] })
class KeysModule {}

const authentication = AuthenticationModule.forRoot();
const authorization = AuthorizationModule.forRoot({ policies: [ArticlePolicy] });

/** The rule: import AuthenticationModule before AuthorizationModule. */
@Module({ imports: [authentication, authorization, KeysModule], controllers: [ArticlesController] })
class AppModule {}

@Module({ imports: [authorization, authentication, KeysModule], controllers: [ArticlesController] })
class WrongOrderAppModule {}

/** An AuthenticationGuard subclass whose name says nothing about authentication. */
@Injectable()
class Gatekeeper extends AuthenticationGuard {}

@Controller('drafts')
@UseGuards(Gatekeeper)
class DraftsController {
  @Post()
  @Can(ArticlePolicy, 'create')
  create() {
    return { created: true };
  }
}

/** The global AuthorizationGuard runs before any @UseGuards(): Gatekeeper comes too late. */
@Module({
  imports: [AuthenticationModule.forRoot({ globalGuard: false }), authorization, KeysModule],
  controllers: [DraftsController],
})
class LateSubclassAppModule {}

/** Authorization denies a handler that declares no check; `@Public()` counts as one. */
@Controller('catalog')
@Can(ArticlePolicy, 'create')
class CatalogController {
  // A @Public() method lifts the class's @Can(), as it lifts the class's authentication.
  @Get('public')
  @Public()
  open() {
    return 'public';
  }

  @Get('anyone')
  @Can.Anyone()
  anyone() {
    return 'anyone';
  }

  @Get('editors')
  editors() {
    return 'editors';
  }
}

@Controller('lobby')
@Public()
class LobbyController {
  @Get()
  landing() {
    return 'landing';
  }

  // Back under authentication, so no longer public: it declares no check.
  @Get('account')
  @Authenticate()
  account() {
    return 'account';
  }
}

@Module({ imports: [authentication, authorization, KeysModule], controllers: [CatalogController, LobbyController] })
class DenyByDefaultAppModule {}

describe.each(adapters.map((a) => a.name))('with @nestjs/authorization (%s)', (adapter) => {
  describe('authentication imported first', () => {
    let app: INestApplication;
    const http = () => request(app.getHttpServer());
    beforeAll(async () => {
      app = await createApp(adapter, AppModule);
    });
    afterAll(() => app.close());

    it('201 for a permitted user (request.user read by defaultGetUser)', async () => {
      await http().post('/articles').set('x-api-key', 'key-ci').expect(201, { created: true });
    });

    it('403 for an authenticated user the policy denies', async () => {
      await http().post('/articles').set('x-api-key', 'key-viewer').expect(403);
    });

    it('401 for anonymous callers on authenticated routes, from authentication (with a challenge)', async () => {
      const res = await http().post('/articles').expect(401);
      expect(res.headers['www-authenticate']).toBe('ApiKey header="x-api-key"');
    });

    it('401 for anonymous callers on optional routes, from authorization (policy got null)', async () => {
      const res = await http().post('/articles/drafts').expect(401);
      expect(res.headers['www-authenticate']).toBeUndefined();
      await http().post('/articles/drafts').set('x-api-key', 'key-viewer').expect(403);
      await http().post('/articles/drafts').set('x-api-key', 'key-ci').expect(201);
    });

    it('200 for guests on @Public routes whose ability allows null', async () => {
      await http().get('/articles').expect(200, []);
    });
  });

  describe('authorization imported first (the mistake)', () => {
    // AuthenticationGuard carries a brand that authorization recognizes, so the
    // order is checked exactly: the app does not start, rather than letting
    // policies see every caller as a guest.
    it('fails at startup, naming the fix', async () => {
      await expect(createApp(adapter, WrongOrderAppModule)).rejects.toThrow(
        /AuthorizationGuard runs before AuthenticationGuard.*import AuthenticationModule before AuthorizationModule/s,
      );
    });

    it('recognizes a subclass by the brand, whatever its name', async () => {
      await expect(createApp(adapter, LateSubclassAppModule)).rejects.toThrow(/AuthorizationGuard runs before Gatekeeper/);
    });
  });
});

describe.each(adapters.map((a) => a.name))('deny by default, with the real @Public() (%s)', (adapter) => {
  let app: INestApplication;
  const errors: unknown[] = [];
  const http = () => request(app.getHttpServer());
  beforeAll(async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation((message: unknown) => {
      errors.push(message);
    });
    app = await createApp(adapter, DenyByDefaultAppModule);
  });
  afterAll(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it("lets guests through a @Public() method, which lifts the class's @Can()", async () => {
    await http().get('/catalog/public').expect(200, 'public');
    await http().get('/lobby').expect(200, 'landing');
  });

  it("applies the class's @Can() elsewhere, and @Can.Anyone() to any signed-in user", async () => {
    await http().get('/catalog/editors').set('x-api-key', 'key-viewer').expect(403);
    await http().get('/catalog/editors').set('x-api-key', 'key-ci').expect(200, 'editors');
    await http().get('/catalog/anyone').set('x-api-key', 'key-viewer').expect(200, 'anyone');
    await http().get('/catalog/anyone').expect(401);
  });

  it('denies a method @Authenticate() takes out of a @Public() class, and names it at startup', async () => {
    await http().get('/lobby/account').expect(401);
    await http().get('/lobby/account').set('x-api-key', 'key-ci').expect(403);
    expect(errors).toEqual([expect.stringContaining('AuthorizationGuard denies every call to LobbyController.account:')]);
  });
});
