import { Inject, Optional, type ExecutionContext } from '@nestjs/common';
import { AuthenticationProvider, PROVIDER_INIT, type ProviderInit } from '../providers/authentication.provider.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { AuthenticationError } from '../errors/authentication.error.js';
import type { AuthenticationResult, MfaState } from '../interfaces/authentication-result.interface.js';
import { JwtError } from '../errors/jwt.error.js';
import type { JwtClaims } from '../interfaces/jwt.interface.js';
import type { JwtSignerOptions } from '../interfaces/jwt-options.interface.js';
import type { JwtBearerProviderOptions } from '../interfaces/jwt-options.interface.js';
import { API_KEY_PATTERN } from '../utils/api-key.util.js';
import { bearerToken } from '../utils/bearer.util.js';
import { hasMfaAmr } from './amr.util.js';
import { JwtVerifier, verifierForSigner } from './jwt-verifier.service.js';

/**
 * Base class for `Authorization: Bearer <jwt>` authentication. Extend it,
 * inject what `validate()` needs, and load the user:
 *
 * ```ts
 * @Injectable()
 * export class JwtAuth extends JwtBearerProvider<User> {
 *   constructor(private readonly users: UsersRepository) {
 *     super(); // verifies the tokens the module's `accessToken` option signs
 *   }
 *   validate(claims: JwtClaims) {
 *     return this.users.findById(claims.sub!);
 *   }
 * }
 * ```
 *
 * Without `key` or `jwks`, it verifies what the module's `accessToken`
 * option issues: the same key, algorithm, issuer, audience and `typ`. For
 * tokens from another issuer, pass them: `super({ jwks, issuer, audience })`
 * (a `jwks` needs both `issuer` and `audience`).
 *
 * Over socket.io it also reads `handshake.auth.token`. A token shaped like
 * an API key (`ApiKeyProvider`) is left to the other providers. `session`
 * is the verified claim set; an `amr` claim containing `mfa`, `otp` or
 * `hwk` marks the result as MFA-verified.
 */
export abstract class JwtBearerProvider<TUser> extends AuthenticationProvider<TUser, JwtClaims> {
  @Optional()
  @Inject(AUTHENTICATION_MODULE_OPTIONS)
  private moduleOptions?: { accessToken?: JwtSignerOptions };
  private verifier?: JwtVerifier;
  private readonly realm: string;

  constructor(private readonly options: JwtBearerProviderOptions = {}) {
    super();
    this.realm = options.realm ?? 'api';
    // `super({ key: process.env.PARTNER_KEY })` with the variable unset must not fall back to the
    // module's `accessToken`: this provider would take the app's own tokens as its issuer's.
    const named = (['key', 'jwks'] as const).filter((name) => Object.hasOwn(options, name));
    if (named.length > 0 && !options.key && !options.jwks) {
      throw new TypeError(
        `${new.target.name}: \`${named.join('` and `')}\` ${named.length > 1 ? 'are' : 'is'} empty: is the environment ` +
          "variable it reads set? Leave both out to verify the tokens the module's `accessToken` issues.",
      );
    }
    if (options.key !== undefined || options.jwks !== undefined) {
      this.verifier = new JwtVerifier(options);
    }
  }

  /** Maps verified claims to the user. `null` (a deleted user) rejects the token. */
  protected abstract validate(claims: JwtClaims): TUser | null | undefined | Promise<TUser | null | undefined>;

  async authenticate(context: ExecutionContext): Promise<AuthenticationResult<TUser, JwtClaims> | null> {
    const token = this.extract(context);
    if (token === undefined) {
      return null;
    }

    let claims: JwtClaims;
    try {
      claims = await this.getVerifier().verify(token);
    } catch (error) {
      if (error instanceof JwtError) {
        this.reject(error.message);
      }
      throw error;
    }

    const user = await this.validate(claims);
    if (user === null || user === undefined) {
      this.reject('unknown subject');
    }

    return { user, session: claims, mfa: this.mfaState(claims) };
  }

  challenge(): string {
    return `Bearer realm="${this.realm}"`;
  }

  protected mfaState(claims: JwtClaims): MfaState | undefined {
    return hasMfaAmr(claims.amr) ? 'verified' : undefined;
  }

  /** @internal */
  [PROVIDER_INIT](resolve: Parameters<ProviderInit>[0]) {
    this.moduleOptions ??= resolve<{ accessToken?: JwtSignerOptions }>(AUTHENTICATION_MODULE_OPTIONS);
    this.getVerifier();
  }

  private getVerifier(): JwtVerifier {
    if (this.verifier) {
      return this.verifier;
    }

    const accessToken = this.moduleOptions?.accessToken;
    if (!accessToken) {
      throw new Error(
        `${this.constructor.name}: nothing to verify tokens with. Configure \`accessToken\` in the ` +
          'AuthenticationModule options, or pass `key` or `jwks` to super().',
      );
    }

    const { realm: _, ...rules } = this.options;
    const defined = Object.fromEntries(Object.entries(rules).filter(([, value]) => value !== undefined));
    this.verifier = verifierForSigner(accessToken, defined);
    return this.verifier;
  }

  private extract(context: ExecutionContext): string | undefined {
    const token = bearerToken(context, this.header(context, 'authorization'));
    if (token === null) {
      this.reject('malformed authorization header');
    }
    // An API key is `ApiKeyProvider`'s, which may run after this one.
    return token === undefined || API_KEY_PATTERN.test(token) ? undefined : token;
  }

  private reject(description: string): never {
    // RFC 6750 §3.1
    throw new AuthenticationError(description, {
      challenge: `Bearer realm="${this.realm}", error="invalid_token", error_description="${description}"`,
    });
  }
}
