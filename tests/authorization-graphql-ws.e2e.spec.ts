/**
 * `@Can()` on GraphQL operations over graphql-ws, behind the real authentication. graphql-ws
 * builds a context per operation, but the `req` in it is the socket's upgrade request, shared by
 * every operation of the socket, like a ws client. A `@Public()` operation authenticates nothing,
 * so it must be a guest, whatever an earlier operation of the socket authenticated and whatever
 * happened to that session since.
 */
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import { Module, type INestApplication } from '@nestjs/common';
import { GraphQLModule, Query, Resolver, Subscription } from '@nestjs/graphql';
import { AuthorizationEvents, AuthorizationModule, Can, Policy, type AuthorizationDeniedEvent } from '@nestjs/authorization';
import { createClient, type Client } from 'graphql-ws';
import request from 'supertest';
import { WebSocket } from 'ws';
import { createApp } from './support/adapters.js';
import { AuthenticationStorage, CurrentUser, Public } from '../lib/index.js';
import { AuthController, AuthProvidersModule, PASSWORDS, UsersModule, authenticationModule, type User } from './fixtures.js';

const typeDefs = /* GraphQL */ `
  type Query {
    draft: String
    peek: String
    whoami: ID
  }
  type Subscription {
    drafts: String
    peeks: String
  }
`;

@Policy()
class DraftPolicy {
  read(user: User | null) {
    return !!user?.roles.includes('editor');
  }
}

@Resolver()
class DraftsResolver {
  @Query('draft')
  @Can(DraftPolicy, 'read')
  draft() {
    return 'Q3 plan';
  }

  // No provider runs: the policy sees a guest, as `@CurrentUser()` would.
  @Public()
  @Query('peek')
  @Can(DraftPolicy, 'read')
  peek() {
    return 'Q3 plan';
  }

  @Public()
  @Query('whoami')
  whoami(@CurrentUser() user: User | null) {
    return user?.id ?? null;
  }

  @Subscription('drafts')
  @Can(DraftPolicy, 'read')
  async *drafts() {
    yield { drafts: 'Q3 plan' };
  }

  @Public()
  @Subscription('peeks')
  @Can(DraftPolicy, 'read')
  async *peeks() {
    yield { peeks: 'Q3 plan' };
  }
}

@Module({
  imports: [
    authenticationModule(),
    AuthorizationModule.forRoot({ policies: [DraftPolicy] }),
    UsersModule,
    AuthProvidersModule,
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      typeDefs,
      subscriptions: { 'graphql-ws': true },
      // Over graphql-ws there is no request per operation: the upgrade request stands in for it.
      context: ({ req, extra }: { req?: unknown; extra?: { request: unknown } }) => ({ req: req ?? extra?.request }),
    }),
  ],
  controllers: [AuthController],
  providers: [DraftsResolver],
})
class DraftsAppModule {}

describe('@Can() on GraphQL over graphql-ws, with @nestjs/authentication', () => {
  let app: INestApplication;
  let url: string;
  const clients: Client[] = [];
  const denials: AuthorizationDeniedEvent[] = [];

  const loginCookie = async (email: string) => {
    const res = await request(app.getHttpServer()).post('/auth/login').send({ email, password: PASSWORDS[email] }).expect(200);
    return (res.headers['set-cookie'] as unknown as string[])[0].split(';')[0];
  };

  /**
   * A graphql-ws client whose socket's upgrade request carries `cookie`. Not lazy: a lazy client
   * closes its socket once no operation is running and opens a new one, with a new upgrade
   * request, for the next. `opened()` counts the sockets it opened.
   */
  const connect = (cookie: string) => {
    let opened = 0;
    const client = createClient({
      url,
      lazy: false,
      retryAttempts: 0,
      on: { connected: () => void opened++ },
      webSocketImpl: class extends WebSocket {
        constructor(address: string, protocols?: string | string[]) {
          super(address, protocols, { headers: { cookie } });
        }
      },
    });
    clients.push(client);

    /** Runs `query` over the socket, to its first result. */
    const run = async (query: string) => {
      const results = client.iterate({ query });
      try {
        return (await results.next()).value;
      } finally {
        await results.return?.();
      }
    };
    return { run, opened: () => opened };
  };
  /** graphql-ws formats no `extensions`: what the client sees of a 401, from either guard. */
  const unauthorized = (field: string) => ({ errors: [expect.objectContaining({ message: 'Unauthorized', path: [field] })] });

  beforeAll(async () => {
    app = await createApp('express', DraftsAppModule);
    url = `ws://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}/graphql`;
    app.get(AuthorizationEvents).events$.subscribe((event) => denials.push(event));
  });
  afterEach(async () => {
    await Promise.all(clients.splice(0).map((client) => client.dispose()));
    denials.length = 0;
  });
  afterAll(() => app.close());

  it('evaluates a @Public() @Can() query after a sign-out everywhere as a guest, with no protected operation in between', async () => {
    const stolen = await loginCookie('alice@example.com'); // the copy someone else holds
    const own = await loginCookie('alice@example.com'); // Alice's browser
    const client = connect(stolen); // the upgrade request carries Alice's session
    expect(await client.run('{ draft }')).toEqual({ data: { draft: 'Q3 plan' } });

    await request(app.getHttpServer()).post('/auth/logout-everywhere').set('Cookie', own).expect(204);
    expect(await client.run('{ peek }')).toEqual({ data: { peek: null }, ...unauthorized('peek') });
    expect(denials).toEqual([
      expect.objectContaining({ policy: 'DraftPolicy', ability: 'read', reason: 'unauthenticated', user: null, handler: 'DraftsResolver.peek' }),
    ]);

    // A protected operation is refused by authentication, before any policy runs.
    expect(await client.run('{ draft }')).toEqual({ data: { draft: null }, ...unauthorized('draft') });
    expect(denials).toHaveLength(1);
    expect(client.opened()).toBe(1); // one socket, one upgrade request, for every operation
  });

  it('evaluates a @Public() @Can() subscription after a sign-out everywhere as a guest', async () => {
    const stolen = await loginCookie('alice@example.com');
    const own = await loginCookie('alice@example.com');
    const client = connect(stolen);
    expect(await client.run('subscription { drafts }')).toEqual({ data: { drafts: 'Q3 plan' } });

    await request(app.getHttpServer()).post('/auth/logout-everywhere').set('Cookie', own).expect(204);
    expect(await client.run('subscription { peeks }')).toEqual(unauthorized('peeks'));
    expect(denials).toEqual([expect.objectContaining({ reason: 'unauthenticated', user: null, handler: 'DraftsResolver.peeks' })]);
    expect(client.opened()).toBe(1);
  });

  it("gives @CurrentUser() of a @Public() operation null, not the user of the socket's last operation", async () => {
    const stolen = await loginCookie('alice@example.com');
    const own = await loginCookie('alice@example.com');
    const client = connect(stolen);
    expect(await client.run('{ draft }')).toEqual({ data: { draft: 'Q3 plan' } });
    // As over HTTP: no provider ran for a @Public() operation, whatever credentials came with it.
    expect(await client.run('{ whoami }')).toEqual({ data: { whoami: null } });
    const overHttp = await request(app.getHttpServer()).post('/graphql').set('Cookie', stolen).send({ query: '{ whoami }' });
    expect(overHttp.body).toEqual({ data: { whoami: null } });

    await request(app.getHttpServer()).post('/auth/logout-everywhere').set('Cookie', own).expect(204);
    expect(await client.run('{ whoami }')).toEqual({ data: { whoami: null } });
    expect(client.opened()).toBe(1);
  });

  it('evaluates concurrent public and protected operations on one socket each as its own', async () => {
    const client = connect(await loginCookie('alice@example.com'));
    expect(await client.run('{ draft }')).toEqual({ data: { draft: 'Q3 plan' } });

    const sessions = app.get(AuthenticationStorage).sessions;
    const getSession = sessions.getSession.bind(sessions);
    const slow = vi.spyOn(sessions, 'getSession').mockImplementationOnce(async (id) => {
      await sleep(40);
      return getSession(id);
    });

    try {
      const protectedOne = client.run('{ draft }'); // still validating the session...
      const publicOne = client.run('{ peek }'); // ...when this one is authorized
      expect(await publicOne).toEqual({ data: { peek: null }, ...unauthorized('peek') });
      expect(await protectedOne).toEqual({ data: { draft: 'Q3 plan' } });
      expect(slow).toHaveBeenCalledTimes(1);
      expect(denials).toEqual([expect.objectContaining({ user: null, handler: 'DraftsResolver.peek' })]);
      expect(client.opened()).toBe(1);
    } finally {
      slow.mockRestore();
    }
  });
});
