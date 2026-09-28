import { Module, type DynamicModule, type OnModuleInit } from '@nestjs/common';
import { APP_INTERCEPTOR, ModuleRef } from '@nestjs/core';
import { EmailVerificationService } from './account/email-verification.service.js';
import { PasswordResetService } from './account/password-reset.service.js';
import {
  ConfigurableModuleClass,
  startupChecks,
  storageRequirements,
  type OPTIONS_TYPE,
} from './authentication.module-definition.js';
import type {
  AuthenticationModuleForRootOptions,
  AuthenticationModuleOptions,
} from './interfaces/authentication-module-options.interface.js';
import { AuthenticationContext } from './context/authentication.context.js';
import { AuthenticationScopeInterceptor } from './interceptors/authentication-scope.interceptor.js';
import { AuthenticationScope } from './context/authentication-scope.service.js';
import { AuthenticationRegistry, LOCK_REGISTRY } from './services/authentication-registry.service.js';
import { AuthenticationStorage, LOCK_STORAGE } from './storage/authentication.storage.js';
import { AuthenticationGuard } from './guards/authentication.guard.js';
import { AUTHENTICATION_MODULE_OPTIONS } from './authentication.constants.js';
import { AuthenticationEvents } from './events/authentication-events.service.js';
import { WsAuthenticator } from './services/ws-authenticator.service.js';
import { TokenService } from './jwt/token.service.js';
import { MagicLinkService } from './magic-link/magic-link.service.js';
import { MfaService } from './mfa/mfa.service.js';
import { OidcService } from './oidc/oidc.service.js';
import { PasswordHasher } from './services/password-hasher.service.js';
import { SessionService } from './session/session.service.js';
import { SignInService } from './session/sign-in.service.js';

/**
 * `AuthenticationModule.forRoot({ session, mfa, … })`, or
 * `forRootAsync({ inject, useFactory })` for values read from config. Global
 * by default. Registers the authentication guard, the interceptor that opens
 * `AuthenticationContext` around each handler, `AuthenticationRegistry`,
 * where the app's credential providers and feature handlers register, and
 * `AuthenticationStorage`, where its stores do.
 *
 * Global enhancers do not reach everywhere by default: a hybrid app's
 * message handlers need `app.connectMicroservice(options, { inheritAppConfig:
 * true })`, and GraphQL field resolvers `fieldResolverEnhancers: ['guards',
 * 'interceptors']`, or the guard does not run there.
 */
@Module({
  providers: [
    startupChecks,
    storageRequirements,
    AuthenticationRegistry,
    AuthenticationStorage,
    AuthenticationScope,
    AuthenticationContext,
    AuthenticationScopeInterceptor,
    { provide: APP_INTERCEPTOR, useExisting: AuthenticationScopeInterceptor },
    AuthenticationGuard,
    AuthenticationEvents,
    WsAuthenticator,
    SessionService,
    SignInService,
    {
      provide: PasswordHasher,
      inject: [AUTHENTICATION_MODULE_OPTIONS],
      useFactory: (options: AuthenticationModuleOptions) => new PasswordHasher(options.password),
    },
    MfaService,
    TokenService,
    EmailVerificationService,
    PasswordResetService,
    MagicLinkService,
    OidcService,
  ],
  exports: [
    AUTHENTICATION_MODULE_OPTIONS,
    AuthenticationRegistry,
    AuthenticationStorage,
    AuthenticationContext,
    AuthenticationGuard,
    AuthenticationEvents,
    WsAuthenticator,
    SessionService,
    SignInService,
    PasswordHasher,
    MfaService,
    TokenService,
    EmailVerificationService,
    PasswordResetService,
    MagicLinkService,
    OidcService,
  ],
})
export class AuthenticationModule extends ConfigurableModuleClass implements OnModuleInit {
  constructor(
    private readonly registry: AuthenticationRegistry,
    private readonly storage: AuthenticationStorage,
    private readonly moduleRef: ModuleRef,
  ) {
    super();
  }

  static forRoot(options: AuthenticationModuleForRootOptions = {}): DynamicModule {
    return super.forRoot(options as typeof OPTIONS_TYPE);
  }

  /**
   * Locks both registries: every provider constructor (where providers,
   * handlers and stores register) has run, and nothing has served a request
   * yet. Fails on a feature missing its handler or its option, logs what
   * registered, and fails in production on in-memory stores a configured
   * feature relies on (see `allowInMemoryStorage`).
   */
  onModuleInit() {
    this.registry[LOCK_REGISTRY]();
    this.storage[LOCK_STORAGE]();
    assertGraphqlContextPerRequest(this.moduleRef);
  }
}

/**
 * The guard authenticates a GraphQL operation from its context's `req`. A
 * `context` given as an object is one object for every request, and
 * `@nestjs/apollo` sets the first request as its `req` and keeps it: every
 * later operation would be authenticated with the first caller's
 * credentials. So such a configuration fails at startup.
 */
function assertGraphqlContextPerRequest(moduleRef: ModuleRef) {
  let options: { context?: unknown } | undefined;
  try {
    options = moduleRef.get<{ context?: unknown }>('GqlModuleOptions', { strict: false });
  } catch {
    return; // no GraphQL module
  }

  if (typeof options?.context === 'object' && options.context !== null) {
    throw new Error(
      'AuthenticationModule: the GraphQL module’s `context` is an object, shared by every request: the first ' +
        'request is kept as its `req`, and every later operation would be authenticated as that caller. Make it a ' +
        'function that builds one per request: `context: ({ req, res }) => ({ req, res, ...yourValues })`.',
    );
  }
}
