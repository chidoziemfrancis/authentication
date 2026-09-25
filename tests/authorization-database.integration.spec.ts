/**
 * Policies over rows a real database returns, on PGlite and on PostgreSQL (a throwaway local
 * cluster, skipped with the reason when the binaries are missing), on Express and Fastify:
 * the README's service checks (load the row, then `authorize()`), its "Lists" recipe (a
 * policy method that returns the query's filter, next to the ability it mirrors), and a
 * policy that injects a repository and reads the database on every check.
 */
import { PGlite } from '@electric-sql/pglite';
import {
  Body,
  Controller,
  Get,
  Inject,
  Injectable,
  Module,
  NotFoundException,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { startPostgres } from './support/postgres.js';
import {
  Authenticate,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentUser,
  type AuthenticationResult,
} from '../lib/index.js';
import {
  AuthorizationEvents,
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
  type AuthorizationDeniedEvent,
} from '@nestjs/authorization';

type User = { id: string; email: string; roles: string[] };
type Post = { id: number; authorId: string; title: string; published: boolean };

interface Database {
  query<T>(sql: string, params?: unknown[]): Promise<T[]>;
  close(): Promise<void>;
}

const DATABASE = Symbol('DATABASE');

const SCHEMA = `
  CREATE TABLE users (id text PRIMARY KEY, email text NOT NULL, roles text[] NOT NULL, banned boolean NOT NULL DEFAULT false);
  CREATE TABLE posts (id serial PRIMARY KEY, author_id text NOT NULL REFERENCES users (id), title text NOT NULL, published boolean NOT NULL);
  INSERT INTO users (id, email, roles) VALUES ('u-alice', 'alice@example.com', '{writer}'), ('u-bob', 'bob@example.com', '{writer}');
  INSERT INTO posts (author_id, title, published) VALUES
    ('u-alice', 'Alice publishes', true),
    ('u-alice', 'Alice drafts', false),
    ('u-bob', 'Bob publishes', true),
    ('u-bob', 'Bob drafts', false);
`;

const POST_COLUMNS = 'id, author_id AS "authorId", title, published';

@Injectable()
class UsersRepository {
  constructor(@Inject(DATABASE) private readonly db: Database) {}

  async findById(id: string): Promise<User | null> {
    const [row] = await this.db.query<User>('SELECT id, email, roles FROM users WHERE id = $1', [id]);
    return row ?? null;
  }

  async isBanned(id: string): Promise<boolean> {
    const [row] = await this.db.query<{ banned: boolean }>('SELECT banned FROM users WHERE id = $1', [id]);
    return row?.banned ?? true;
  }
}

/** Authenticates `x-user: <id>` against the users table. */
@Injectable()
class HeaderAuth extends AuthenticationProvider<User> {
  constructor(
    private readonly usersRepository: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super();
    registry.registerProvider(this);
  }

  async authenticate(context: ExecutionContext): Promise<AuthenticationResult<User> | null> {
    const id = this.header(context, 'x-user');
    const user = id ? await this.usersRepository.findById(id) : null;
    return user ? { user } : null;
  }
}

@Policy()
class PostPolicy {
  view(user: User | null, post: Post) {
    return post.published || post.authorId === user?.id;
  }

  update(user: User, post: Post) {
    return post.authorId === user.id;
  }

  // The posts `view` allows, as a WHERE clause. Not an ability: it doesn't return a boolean.
  viewable(user: User | null): { where: string; params: unknown[] } {
    return user ? { where: 'published OR author_id = $1', params: [user.id] } : { where: 'published', params: [] };
  }
}

@Policy()
class CommentPolicy {
  constructor(private readonly usersRepository: UsersRepository) {}

  async create(user: User | null) {
    return !!user && !(await this.usersRepository.isBanned(user.id));
  }
}

@Injectable()
class PostsService {
  constructor(
    @Inject(DATABASE) private readonly db: Database,
    private readonly postPolicy: PostPolicy,
    private readonly authorizationService: AuthorizationService,
  ) {}

  findAll(user: User | null) {
    const { where, params } = this.postPolicy.viewable(user);
    return this.db.query<Post>(`SELECT ${POST_COLUMNS} FROM posts WHERE ${where} ORDER BY id`, params);
  }

  async findOne(user: User | null, id: number) {
    const post = await this.findOrThrow(id);
    await this.authorizationService.authorize(PostPolicy, 'view', user, post);
    return post;
  }

  async rename(user: User, id: number, title: string) {
    const post = await this.findOrThrow(id);
    await this.authorizationService.authorize(PostPolicy, 'update', user, post);
    const [updated] = await this.db.query<Post>(`UPDATE posts SET title = $2 WHERE id = $1 RETURNING ${POST_COLUMNS}`, [id, title]);
    return updated;
  }

  private async findOrThrow(id: number) {
    const [post] = await this.db.query<Post>(`SELECT ${POST_COLUMNS} FROM posts WHERE id = $1`, [id]);
    if (!post) {
      throw new NotFoundException();
    }
    return post;
  }
}

@Controller('posts')
class PostsController {
  constructor(private readonly postsService: PostsService) {}

  @Get()
  @Authenticate({ optional: true })
  findAll(@CurrentUser() user: User | null) {
    return this.postsService.findAll(user);
  }

  @Get(':id')
  @Authenticate({ optional: true })
  findOne(@CurrentUser() user: User | null, @Param('id', ParseIntPipe) id: number) {
    return this.postsService.findOne(user, id);
  }

  @Patch(':id')
  rename(@CurrentUser() user: User, @Param('id', ParseIntPipe) id: number, @Body() body: { title: string }) {
    return this.postsService.rename(user, id, body.title);
  }

  @Post(':id/comments')
  @Can(CommentPolicy, 'create')
  comment() {
    return { commented: true };
  }
}

const appModuleFor = (db: Database) => {
  @Module({
    providers: [{ provide: DATABASE, useValue: db }, UsersRepository],
    exports: [DATABASE, UsersRepository],
  })
  class DatabaseModule {}

  @Module({
    imports: [DatabaseModule],
    controllers: [PostsController],
    providers: [HeaderAuth, PostsService, PostPolicy, CommentPolicy],
  })
  class PostsModule {}

  @Module({ imports: [AuthenticationModule.forRoot(), AuthorizationModule.forRoot(), PostsModule] })
  class AppModule {}

  return AppModule;
};

async function pgliteDatabase(): Promise<Database> {
  const client = new PGlite();
  await client.exec(SCHEMA);
  return {
    query: async <T>(sql: string, params: unknown[] = []) => (await client.query<T>(sql, params)).rows,
    close: () => client.close(),
  };
}

const { postgres, reason } = await startPostgres();
afterAll(() => postgres?.stop());

async function postgresDatabase(name: string): Promise<Database> {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: await postgres!.createDatabase(name), max: 4 });
  await pool.query(SCHEMA);
  return {
    query: async <T>(sql: string, params: unknown[] = []) => (await pool.query(sql, params)).rows as T[],
    close: () => pool.end(),
  };
}

const targets = [
  { name: 'PGlite', open: (_adapter: string) => pgliteDatabase() },
  {
    name: `PostgreSQL${postgres ? '' : ` (skipped: ${reason})`}`,
    skip: !postgres,
    open: (adapter: string) => postgresDatabase(`authorization_${adapter}`),
  },
];

describe.each(targets)('policies over database rows: $name', (target) => {
  describe.skipIf(!!target.skip).each(adapters.map((a) => a.name))('%s', (adapter) => {
    let db: Database;
    let app: INestApplication;
    const events: AuthorizationDeniedEvent[] = [];
    const http = () => request(app.getHttpServer());
    const titleOf = async (id: number) => (await db.query<{ title: string }>('SELECT title FROM posts WHERE id = $1', [id]))[0].title;

    beforeAll(async () => {
      db = await target.open(adapter);
      app = await createApp(adapter, appModuleFor(db));
      app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
    }, 60_000); // PGlite loads its WASM on first open: slow under a parallel run
    afterAll(async () => {
      await app?.close();
      await db?.close();
    });
    beforeEach(() => {
      events.length = 0;
    });

    it("filters lists in the query with the policy's filter, not row by row", async () => {
      const titles = (body: Post[]) => body.map(({ title }) => title);

      expect(titles((await http().get('/posts').expect(200)).body)).toEqual(['Alice publishes', 'Bob publishes']);
      expect(titles((await http().get('/posts').set('x-user', 'u-alice').expect(200)).body)).toEqual([
        'Alice publishes',
        'Alice drafts',
        'Bob publishes',
      ]);
      expect(events).toEqual([]);
    });

    it('loads the row, then authorizes it: 404 before any check, then 401, 403 or 200', async () => {
      await http().get('/posts/999').expect(404);
      await http().get('/posts/2').expect(401, { message: 'Unauthorized', statusCode: 401 });
      await http().get('/posts/2').set('x-user', 'u-bob').expect(403, { message: 'Forbidden', statusCode: 403 });
      await http().get('/posts/2').set('x-user', 'u-alice').expect(200, { id: 2, authorId: 'u-alice', title: 'Alice drafts', published: false });
      await http().get('/posts/3').expect(200);

      expect(events).toEqual([
        { type: 'denied', policy: 'PostPolicy', ability: 'view', reason: 'unauthenticated', user: null, args: [{ id: 2, authorId: 'u-alice', title: 'Alice drafts', published: false }] },
        {
          type: 'denied',
          policy: 'PostPolicy',
          ability: 'view',
          reason: 'forbidden',
          user: { id: 'u-bob', email: 'bob@example.com', roles: ['writer'] },
          args: [{ id: 2, authorId: 'u-alice', title: 'Alice drafts', published: false }],
        },
      ]);
    });

    it('writes nothing when authorize() denies, and writes when it allows', async () => {
      await http().patch('/posts/1').set('x-user', 'u-bob').send({ title: 'Hijacked' }).expect(403);
      expect(await titleOf(1)).toBe('Alice publishes');

      await http().patch('/posts/1').set('x-user', 'u-alice').send({ title: 'Alice renames' }).expect(200, {
        id: 1,
        authorId: 'u-alice',
        title: 'Alice renames',
        published: true,
      });
      expect(await titleOf(1)).toBe('Alice renames');
    });

    it('lets a @Can() policy read the database through an injected repository on every check', async () => {
      await http().post('/posts/1/comments').set('x-user', 'u-bob').expect(201, { commented: true });

      await db.query("UPDATE users SET banned = true WHERE id = 'u-bob'");
      await http().post('/posts/1/comments').set('x-user', 'u-bob').expect(403);

      await db.query("UPDATE users SET banned = false WHERE id = 'u-bob'");
      await http().post('/posts/1/comments').set('x-user', 'u-bob').expect(201);

      expect(events).toEqual([expect.objectContaining({ policy: 'CommentPolicy', ability: 'create', handler: 'PostsController.comment' })]);
    });
  });
});
