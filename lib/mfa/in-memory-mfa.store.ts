import { Injectable } from '@nestjs/common';
import type { TotpRecord, MfaStore } from '../interfaces/mfa-store.interface.js';

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Atomic because it is synchronous.
 */
@Injectable()
export class InMemoryMfaStore implements MfaStore {
  private readonly totp = new Map<string, TotpRecord>();
  private readonly codes = new Map<string, Set<string>>();
  private readonly failuresAt = new Map<string, number[]>();

  async getTotp(userId: string) {
    const record = this.totp.get(userId);
    return record && { ...record };
  }
  async saveTotp(userId: string, record: TotpRecord | null) {
    if (!record) {
      this.totp.delete(userId);
      return;
    }

    const claimed = this.totp.get(userId)?.lastUsedStep;
    const lastUsedStep = Math.max(claimed ?? -Infinity, record.lastUsedStep ?? -Infinity);
    const { lastUsedStep: _, ...rest } = record;
    this.totp.set(userId, { ...rest, ...(Number.isFinite(lastUsedStep) && { lastUsedStep }) });
  }
  async claimTotpStep(userId: string, step: number) {
    const record = this.totp.get(userId);
    if (!record || (record.lastUsedStep !== undefined && step <= record.lastUsedStep)) {
      return false;
    }
    record.lastUsedStep = step;
    return true;
  }
  async saveRecoveryCodes(userId: string, hashes: string[]) {
    if (hashes.length === 0) {
      this.codes.delete(userId);
    } else {
      this.codes.set(userId, new Set(hashes));
    }
  }
  async consumeRecoveryCode(userId: string, hash: string) {
    return this.codes.get(userId)?.delete(hash) ?? false;
  }
  async countRecoveryCodes(userId: string) {
    return this.codes.get(userId)?.size ?? 0;
  }
  async recordMfaFailure(userId: string, windowMs: number, now: number) {
    const recent = this.recent(userId, windowMs, now);
    recent.push(now);
    this.failuresAt.set(userId, recent);
    return recent.length;
  }
  async countMfaFailures(userId: string, windowMs: number, now: number) {
    return this.recent(userId, windowMs, now).length;
  }
  async clearMfaFailures(userId: string) {
    this.failuresAt.delete(userId);
  }
  private recent(userId: string, windowMs: number, now: number) {
    return (this.failuresAt.get(userId) ?? []).filter((t) => t > now - windowMs);
  }
}
