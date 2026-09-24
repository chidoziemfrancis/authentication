import { Injectable } from '@nestjs/common';
import type { MagicLinkRecord, MagicLinkStore } from '../interfaces/magic-link-store.interface.js';

const MAX_PENDING = 10_000;

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Drops expired links as new ones are saved, and holds at most
 * 10,000, dropping the oldest: anyone can request links, so the store must
 * not grow with them.
 */
@Injectable()
export class InMemoryMagicLinkStore implements MagicLinkStore {
  private readonly links = new Map<string, MagicLinkRecord>();

  async saveMagicLink(record: MagicLinkRecord) {
    const now = record.createdAt.getTime();
    // Insertion order is expiry order (one lifetime per service): stop at the first live entry.
    for (const [id, link] of this.links) {
      if (link.expiresAt.getTime() > now) {
        break;
      }
      this.links.delete(id);
    }

    this.links.set(record.id, { ...record });
    for (const id of this.links.keys()) {
      if (this.links.size <= MAX_PENDING) {
        break;
      }
      this.links.delete(id); // insertion order: the oldest first
    }
  }

  async consumeMagicLink(id: string) {
    const record = this.links.get(id);
    this.links.delete(id);
    return record;
  }
}
