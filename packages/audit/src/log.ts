import {
  buildRecord,
  GENESIS_PREV_HASH,
  verifyChain,
  type ChainHead,
  type ChainPosition,
  type ChainVerifyResult,
} from './chain';
import { EpochMs, Id } from './primitives';
import {
  SequenceConflictError,
  type AuditStore,
  type ListOptions,
} from './store';
import { AuditEvent, AuditRecord } from './types';

export type AuditLogOptions = {
  readonly store: AuditStore;
  /** Injected clock returning epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
};

export type AppendErrorCode =
  | 'INVALID_EVENT'
  | 'INVALID_TIMESTAMP'
  | 'STORE_ERROR';

export type AppendResult =
  | { ok: true; record: AuditRecord }
  | { ok: false; code: AppendErrorCode; message: string };

export type VerifyLogOptions = {
  readonly expectedHead?: ChainHead;
  readonly pageSize?: number;
};

export interface AuditLog {
  /**
   * Validates, hash-chains, and persists an audit event.
   *
   * **Fail-closed rule:** If `append` returns `ok: false`, the caller must NOT
   * perform the guarded action.
   */
  append(event: AuditEvent): Promise<AppendResult>;
  head(engagementId: string): Promise<AuditRecord | null>;
  list(
    engagementId: string,
    options?: ListOptions,
  ): Promise<readonly AuditRecord[]>;
  verify(
    engagementId: string,
    options?: VerifyLogOptions,
  ): Promise<ChainVerifyResult>;
}

const DEFAULT_PAGE_SIZE = 1000;
const MAX_CONFLICT_ATTEMPTS = 5;

/**
 * Creates a fail-closed, hash-chained audit log backed by `store`.
 * Concurrent `append` calls for the same `engagementId` are serialized in-process
 * as an optimization; `SequenceConflictError` retries handle cross-process races.
 */
export function createAuditLog(options: AuditLogOptions): AuditLog {
  const { store, now = Date.now } = options;
  const locks = new Map<string, Promise<void>>();

  function serialize<T>(engagementId: string, fn: () => Promise<T>): Promise<T> {
    const previous = locks.get(engagementId) ?? Promise.resolve();
    const next = previous.then(fn, fn);
    const tail = next.then(
      () => undefined,
      () => undefined,
    );
    locks.set(engagementId, tail);
    void tail.then(() => {
      if (locks.get(engagementId) === tail) {
        locks.delete(engagementId);
      }
    });
    return next;
  }

  return {
    async append(event: AuditEvent): Promise<AppendResult> {
      const parsed = AuditEvent.safeParse(event);
      if (!parsed.success) {
        return {
          ok: false,
          code: 'INVALID_EVENT',
          message: 'Invalid audit event',
        };
      }

      const validEvent = parsed.data;

      return serialize(validEvent.engagementId, async () => {
        for (let attempt = 0; attempt < MAX_CONFLICT_ATTEMPTS; attempt++) {
          let rawPrev: AuditRecord | null;
          try {
            rawPrev = await store.head(validEvent.engagementId);
          } catch {
            return {
              ok: false,
              code: 'STORE_ERROR',
              message: 'Failed to read chain head',
            };
          }

          let prev: AuditRecord | null = null;
          if (rawPrev !== null) {
            const parsedPrev = AuditRecord.safeParse(rawPrev);
            if (
              !parsedPrev.success ||
              parsedPrev.data.engagementId !== validEvent.engagementId
            ) {
              return {
                ok: false,
                code: 'STORE_ERROR',
                message: 'Store returned an invalid chain head',
              };
            }
            prev = parsedPrev.data;
          }

          let rawTimestamp: number;
          try {
            rawTimestamp = now();
          } catch {
            return {
              ok: false,
              code: 'INVALID_TIMESTAMP',
              message: 'Clock returned an invalid timestamp',
            };
          }

          if (!EpochMs.safeParse(rawTimestamp).success) {
            return {
              ok: false,
              code: 'INVALID_TIMESTAMP',
              message: 'Clock returned an invalid timestamp',
            };
          }

          // Clamp backwards clock steps to preserve chain monotonicity without
          // triggering an audit outage on minor NTP adjustments.
          const timestamp =
            prev !== null
              ? Math.max(rawTimestamp, prev.timestamp)
              : rawTimestamp;

          const seq = prev ? prev.seq + 1 : 0;
          const prevHash = prev ? prev.hash : GENESIS_PREV_HASH;

          let record: AuditRecord;
          try {
            record = buildRecord(validEvent, { seq, prevHash, timestamp });
          } catch {
            return {
              ok: false,
              code: 'INVALID_EVENT',
              message: 'Failed to build audit record',
            };
          }

          try {
            await store.append(record);
            return { ok: true, record };
          } catch (err) {
            if (err instanceof SequenceConflictError) {
              continue;
            }
            return {
              ok: false,
              code: 'STORE_ERROR',
              message: 'Failed to append audit record',
            };
          }
        }

        return {
          ok: false,
          code: 'STORE_ERROR',
          message: 'Failed to append audit record',
        };
      });
    },

    async head(engagementId: string): Promise<AuditRecord | null> {
      const record = await store.head(engagementId);
      return record === null ? null : AuditRecord.parse(record);
    },

    async list(
      engagementId: string,
      listOptions?: ListOptions,
    ): Promise<readonly AuditRecord[]> {
      const records = await store.list(engagementId, listOptions);
      return records.map((r) => AuditRecord.parse(r));
    },

    async verify(
      engagementId: string,
      verifyOptions: VerifyLogOptions = {},
    ): Promise<ChainVerifyResult> {
      if (!Id.safeParse(engagementId).success) {
        return {
          ok: false,
          index: -1,
          code: 'INVALID_OPTIONS',
          message: 'Invalid options: engagementId',
        };
      }

      const pageSize = verifyOptions.pageSize ?? DEFAULT_PAGE_SIZE;
      if (!Number.isInteger(pageSize) || pageSize <= 0) {
        return {
          ok: false,
          index: -1,
          code: 'INVALID_OPTIONS',
          message: 'Invalid options: pageSize must be a positive integer',
        };
      }

      let from: ChainPosition = {
        seq: 0,
        prevHash: GENESIS_PREV_HASH,
        timestamp: 0,
      };
      let totalCount = 0;
      let headSeq: number | null = null;
      let headHash: string | null = null;

      while (true) {
        let page: readonly AuditRecord[];
        try {
          page = await store.list(engagementId, {
            fromSeq: from.seq,
            limit: pageSize,
          });
        } catch {
          return {
            ok: false,
            index: totalCount,
            code: 'STORE_ERROR',
            message: 'Failed to read audit records',
          };
        }

        if (page.length === 0) {
          break;
        }

        const result = verifyChain(page, { engagementId, from });
        if (!result.ok) {
          return {
            ...result,
            index:
              result.index >= 0 ? totalCount + result.index : result.index,
          };
        }

        totalCount += result.count;
        headSeq = result.headSeq;
        headHash = result.headHash;

        const last = page[page.length - 1]!;
        from = {
          seq: last.seq + 1,
          prevHash: last.hash,
          timestamp: last.timestamp,
        };
      }

      if (verifyOptions.expectedHead !== undefined) {
        if (totalCount === 0 || headSeq === null || headHash === null) {
          return {
            ok: false,
            index: 0,
            code: 'HEAD_MISMATCH',
            message: 'Chain is empty but a head was expected',
          };
        }
        if (headSeq !== verifyOptions.expectedHead.seq) {
          return {
            ok: false,
            index: totalCount,
            seq: headSeq,
            code: 'HEAD_MISMATCH',
            message: `Chain ends at seq ${headSeq}, expected ${verifyOptions.expectedHead.seq}`,
          };
        }
        if (headHash !== verifyOptions.expectedHead.hash) {
          return {
            ok: false,
            index: totalCount,
            seq: headSeq,
            code: 'HEAD_MISMATCH',
            message: `Head hash differs at seq ${headSeq}`,
          };
        }
      }

      return {
        ok: true,
        count: totalCount,
        headSeq,
        headHash,
      };
    },
  };
}
