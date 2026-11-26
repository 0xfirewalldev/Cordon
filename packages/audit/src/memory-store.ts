import { GENESIS_PREV_HASH } from './chain';
import {
  SequenceConflictError,
  type AuditStore,
  type ListOptions,
} from './store';
import { AuditRecord } from './types';

function assertNonNegativeInt(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative integer`);
  }
}

/**
 * In-memory `AuditStore` for tests and local development.
 * Enforces contiguous `seq` and `prevHash` linkage on append and clones records
 * across boundaries so external mutations cannot corrupt stored history.
 */
export class InMemoryAuditStore implements AuditStore {
  private readonly chains = new Map<string, AuditRecord[]>();

  async head(engagementId: string): Promise<AuditRecord | null> {
    const chain = this.chains.get(engagementId);
    if (!chain || chain.length === 0) {
      return null;
    }
    const last = chain[chain.length - 1];
    return last ? structuredClone(last) : null;
  }

  async append(record: AuditRecord): Promise<void> {
    const parsed = AuditRecord.parse(record);
    const chain = this.chains.get(parsed.engagementId) ?? [];
    const prev = chain[chain.length - 1];

    const expectedSeq = prev ? prev.seq + 1 : 0;
    if (parsed.seq !== expectedSeq) {
      throw new SequenceConflictError(
        `Sequence conflict for engagement ${parsed.engagementId}: expected ${expectedSeq}, got ${parsed.seq}`,
      );
    }

    const expectedPrevHash = prev ? prev.hash : GENESIS_PREV_HASH;
    if (parsed.prevHash !== expectedPrevHash) {
      throw new SequenceConflictError(
        `prevHash mismatch for engagement ${parsed.engagementId} at seq ${parsed.seq}`,
      );
    }

    chain.push(structuredClone(parsed));
    this.chains.set(parsed.engagementId, chain);
  }

  async list(
    engagementId: string,
    options: ListOptions = {},
  ): Promise<readonly AuditRecord[]> {
    const fromSeq = options.fromSeq ?? 0;
    assertNonNegativeInt(fromSeq, 'fromSeq');

    if (options.limit !== undefined) {
      assertNonNegativeInt(options.limit, 'limit');
      if (options.limit === 0) {
        return [];
      }
    }

    const chain = this.chains.get(engagementId);
    if (!chain || chain.length === 0 || fromSeq >= chain.length) {
      return [];
    }

    const slice =
      options.limit !== undefined
        ? chain.slice(fromSeq, fromSeq + options.limit)
        : chain.slice(fromSeq);

    return slice.map((r) => structuredClone(r));
  }
}

export function createMemoryStore(): InMemoryAuditStore {
  return new InMemoryAuditStore();
}
