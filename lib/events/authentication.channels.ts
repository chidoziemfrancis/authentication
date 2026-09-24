import { channel, type Channel } from 'node:diagnostics_channel';
import type { AuthenticationEvent } from './authentication-events.interface.js';

const channels = new Map<string, Channel>();

/** `nestjs:authentication:<type>`, one `node:diagnostics_channel` channel per event. */
export function channelFor(type: AuthenticationEvent['type']): Channel {
  let found = channels.get(type);
  if (!found) {
    found = channel(`nestjs:authentication:${type}`);
    channels.set(type, found);
  }
  return found;
}
