/** The resolved module options: what `forRoot()` received, or what `forRootAsync()`'s factory returned. */
export const AUTHENTICATION_MODULE_OPTIONS = 'AUTHENTICATION_MODULE_OPTIONS';

/** @internal The storage contracts the configured features use, for `AuthenticationStorage`'s production guard. */
export const AUTHENTICATION_STORAGE_REQUIREMENTS = Symbol('AUTHENTICATION_STORAGE_REQUIREMENTS');

/** @internal Route metadata written by `@Public()` and `@Authenticate()`. */
export const AUTHENTICATION_METADATA = 'authentication:route';

/**
 * @internal The static brand on `AuthenticationGuard`, which subclasses
 * inherit. `@nestjs/authorization` recognizes the guard by it, without
 * importing this package or relying on the class name. A registry symbol,
 * so every copy of either package agrees on it.
 */
export const AUTHENTICATION_GUARD_BRAND = Symbol.for('@nestjs/authentication:guard');
