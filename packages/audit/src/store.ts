import type { AuditRecord } from './types';

export type ListOptions = {
  /** Inclusive starting sequence number. Defaults to 0. */
  readonly fromSeq?: number;
  /** Maximum number of records to return. */
  readonly limit?: number;
};

/**
 * Thrown by `AuditStore.append` when another writer appended the same `seq`
 * or advanced the chain head concurrently.
 */
export class SequenceConflictError extends Error {
  constructor(message = 'Audit sequence conflict') {
    super(message);
    this.name = 'SequenceConflictError';
  }
}

/**
 * Append-only persistence contract for per-engagement audit chains.
 */
export interface AuditStore {
  /** Returns the latest record for an engagement, or `null` if the chain is empty. */
  head(engagementId: string): Promise<AuditRecord | null>;

  /**
   * Atomically persists the next record in an engagement's chain.
   * Implementations must throw `SequenceConflictError` on `seq` or `prevHash` conflict.
   */
  append(record: AuditRecord): Promise<void>;

  /**
   * Returns records for an engagement in ascending `seq` order.
   * Implementations may return fewer than `limit` records even when more remain;
   * callers must continue until an empty array is returned.
   */
  list(
    engagementId: string,
    options?: ListOptions,
  ): Promise<readonly AuditRecord[]>;
}
