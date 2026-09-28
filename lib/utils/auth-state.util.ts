import type { ExecutionContext } from '@nestjs/common';
import { scopedResult } from '../context/authentication-scope.service.js';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';

const AUTH_STATE = Symbol.for('nestjs.authentication.state');
/** The `session` this package last mirrored on a carrier, to tell it from another package's. */
const MIRRORED_SESSION = Symbol.for('nestjs.authentication.mirrored-session');
/**
 * Where a ws client carries {@link userOf}, for other packages to call without importing this
 * one (`@nestjs/authorization` does). A registry symbol, so every copy of either package agrees.
 */
const USER_OF = Symbol.for('nestjs.authentication.userOf');

type Headers = Record<string, string | string[] | undefined>;
type State = AuthenticationResult<any, any> | null;

/**
 * Per-call state. For HTTP, RPC and GraphQL the carrier below is already
 * per call. A WebSocket carrier is the socket, which outlives the message and
 * is shared by concurrent messages, so ws calls are also keyed by their
 * message payload (the same object reaches guards, interceptors and param
 * decorators) or, for primitive payloads, by the args array (shared by
 * guards and interceptors).
 */
const perCall = new WeakMap<object, State>();

function callKeys(context: ExecutionContext): object[] {
  if (context.getType() !== 'ws') {
    return [];
  }

  const data = context.switchToWs().getData();
  const keys: object[] = [context.getArgs()];
  if (typeof data === 'object' && data !== null) {
    keys.push(data);
  }
  return keys;
}

/**
 * The object that carries the result for one call, mirrored as `user` /
 * `session` where Passport-era code and `@nestjs/authorization` look:
 * the request (http), the client socket (ws), the transport context (rpc),
 * `context.req` (graphql).
 */
function carrierOf(context: ExecutionContext): Record<PropertyKey, any> | undefined {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest();
    case 'ws':
      return context.switchToWs().getClient();
    case 'rpc': {
      const ctx = context.switchToRpc().getContext();
      return typeof ctx === 'object' && ctx !== null ? ctx : undefined;
    }
    case 'graphql':
      return context.getArgByIndex(2)?.req;
    default:
      return undefined;
  }
}

/**
 * Records what the handler sees (`@CurrentUser()`, `AuthContext`,
 * `request.user`). `perCallOnly` skips the carrier mirror; used for ws
 * `@Public()` messages, so they do not clear `client.user` under a
 * concurrent message on the same socket.
 */
export function setAuthState(context: ExecutionContext, result: State, { perCallOnly = false } = {}) {
  for (const key of callKeys(context)) {
    perCall.set(key, result);
  }

  const carrier = carrierOf(context);
  if (!carrier) {
    return;
  }

  if (context.getType() === 'ws') {
    // A function of the message, not a user: safe on the socket that concurrent messages share.
    carrier[USER_OF] = userOf;
  }
  if (perCallOnly) {
    return;
  }

  carrier[AUTH_STATE] = result;
  carrier.user = result?.user ?? null;
  // `request.session` is often another package's (express-session, @fastify/session): mirrored only
  // where it is free, or still holds what this package put there.
  if (!('session' in carrier) || carrier.session === carrier[MIRRORED_SESSION]) {
    carrier.session = result?.session ?? null;
    carrier[MIRRORED_SESSION] = carrier.session;
  }
}

/**
 * `undefined` when authentication has not run for this call, `null` when it
 * ran and the caller is anonymous.
 */
export function getAuthState(context: ExecutionContext): State | undefined {
  for (const key of callKeys(context)) {
    if (perCall.has(key)) {
      return perCall.get(key);
    }
  }

  const carrier = carrierOf(context);
  return carrier && AUTH_STATE in carrier ? carrier[AUTH_STATE] : undefined;
}

/**
 * @internal This call's result: the scope the interceptor opened for it, else what the guard
 * recorded on the carrier. A ws message whose payload is a primitive shares nothing else with its
 * guard but the socket, which outlives it, and would otherwise read another message's user.
 */
export function resultOf(context: ExecutionContext): State | undefined {
  const scoped = scopedResult(context);
  return scoped !== undefined ? scoped : getAuthState(context);
}

/**
 * The user of one ws message, for other packages: they call `client[USER_OF](context)` on a
 * client this package has recorded a result on. The client is the connection, so its `user` is
 * whatever the last authenticated message left, and a `@Public()` message leaves it alone. This
 * answers what `@CurrentUser()` gets instead: the message's user, `null` when the message is
 * anonymous (a `@Public()` one is), and `undefined` when nothing was recorded, for the message
 * or its connection.
 */
function userOf(context: ExecutionContext): unknown {
  const result = resultOf(context);
  return result === undefined ? undefined : (result?.user ?? null);
}

const RAW = Symbol.for('nestjs.authentication.raw');
const rawPerCall = new WeakMap<object, State>();

/**
 * The providers' unfiltered answer, cached so a guard applied twice (global
 * plus `@UseGuards`, or GraphQL root and field resolvers sharing one
 * operation's context) authenticates once. Per message for ws, and per
 * operation for GraphQL: over graphql-ws one upgrade request serves every
 * operation of the socket, and each must see a revocation.
 */
export function setRawResult(context: ExecutionContext, result: State) {
  if (context.getType() === 'ws') {
    for (const key of callKeys(context)) {
      rawPerCall.set(key, result);
    }
    return;
  }

  const carrier = rawCarrierOf(context);
  if (carrier) {
    carrier[RAW] = result;
  }
}

export function getRawResult(context: ExecutionContext): State | undefined {
  if (context.getType() === 'ws') {
    for (const key of callKeys(context)) {
      if (rawPerCall.has(key)) {
        return rawPerCall.get(key);
      }
    }
    return undefined;
  }

  const carrier = rawCarrierOf(context);
  return carrier && RAW in carrier ? carrier[RAW] : undefined;
}

/** Where the raw answer is cached: the GraphQL operation's context, else the call's carrier. */
function rawCarrierOf(context: ExecutionContext): Record<PropertyKey, any> | undefined {
  if (context.getType<string>() === 'graphql') {
    const operation = context.getArgByIndex(2);
    return typeof operation === 'object' && operation !== null ? operation : undefined;
  }
  return carrierOf(context);
}

/**
 * Request headers for the transports that have them:
 * - `http`: `request.headers`
 * - `ws`: socket.io's `client.handshake.headers`, else `client.request.headers`
 *   (`WsAuthenticator.authenticateConnection()` stores the upgrade request
 *   there for the `ws` library)
 * - `graphql`: `context.req.headers`
 * - `rpc`: `undefined`; metadata is transport specific
 */
export function getRequestHeaders(context: ExecutionContext): Headers | undefined {
  return requestOf(context)?.headers;
}

/**
 * The request behind a call, as far as authentication needs it: headers,
 * and the method for HTTP and GraphQL (a WebSocket handshake has none, so
 * it counts as a safe request). `undefined` for RPC.
 */
export function requestOf(context: ExecutionContext): { headers: Headers; method?: string } | undefined {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest();
    case 'ws': {
      const client = context.switchToWs().getClient();
      const headers = client?.handshake?.headers ?? client?.request?.headers;
      return headers ? { headers } : undefined;
    }
    case 'graphql':
      return context.getArgByIndex(2)?.req;
    default:
      return undefined;
  }
}

export function firstHeader(headers: Headers | undefined, name: string): string | undefined {
  const value = headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}
