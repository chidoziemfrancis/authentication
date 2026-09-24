import type { ExecutionContext } from '@nestjs/common';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';

const AUTH_STATE = Symbol.for('nestjs.authentication.state');

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

  if (perCallOnly) {
    return;
  }

  const carrier = carrierOf(context);
  if (!carrier) {
    return;
  }

  carrier[AUTH_STATE] = result;
  carrier.user = result?.user ?? null;
  carrier.session = result?.session ?? null;
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

const RAW = Symbol.for('nestjs.authentication.raw');
const rawPerCall = new WeakMap<object, State>();

/**
 * The providers' unfiltered answer, cached so a guard applied twice (global
 * plus `@UseGuards`, or GraphQL root and field resolvers sharing
 * `context.req`) authenticates once. Per message for ws.
 */
export function setRawResult(context: ExecutionContext, result: State) {
  if (context.getType() === 'ws') {
    for (const key of callKeys(context)) {
      rawPerCall.set(key, result);
    }
    return;
  }

  const carrier = carrierOf(context);
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

  const carrier = carrierOf(context);
  return carrier && RAW in carrier ? carrier[RAW] : undefined;
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
