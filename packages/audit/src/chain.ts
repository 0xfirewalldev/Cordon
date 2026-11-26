import { canonicalJson, sha256Hex } from '@scope-guard/canonical';
import { z } from 'zod';
import { EpochMs, Id, Sha256Hash } from './primitives';
import { AuditEvent, AuditRecord } from './types';
import { show } from './util';

/** `prevHash` of the genesis record (seq 0): 64 lowercase hex zeros. */
export const GENESIS_PREV_HASH = '0'.repeat(64);

/**
 * Prefix of every hashed string. If the serialization or the set of hashed
 * fields ever changes, bump the version, so a record can never verify under
 * two different formats.
 */
const FORMAT_TAG = 'scope-guard.audit.v1\n';

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown
  ? Omit<T, K>
  : never;

/** An AuditRecord without its hash. Distributive, so each type keeps its own payload. */
export type UnsignedRecord = DistributiveOmit<AuditRecord, 'hash'>;

export type ChainErrorCode =
  | 'INVALID_OPTIONS'
  | 'INVALID_RECORD'
  | 'ENGAGEMENT_MISMATCH'
  | 'SEQ_MISMATCH'
  | 'PREV_HASH_MISMATCH'
  | 'TIMESTAMP_REGRESSION'
  | 'HASH_MISMATCH'
  | 'HEAD_MISMATCH';

/** Where records[0] must sit: its seq, the hash it must link to, and the previous timestamp. */
export type ChainPosition = {
  readonly seq: number;
  readonly prevHash: string;
  readonly timestamp: number;
};

/** The externally anchored head of the chain. */
export type ChainHead = { readonly seq: number; readonly hash: string };

export type VerifyOptions = {
  /** The engagement this chain must belong to. Never inferred from the data. */
  readonly engagementId: string;
  /** Resume point. Defaults to genesis: { seq: 0, prevHash: GENESIS_PREV_HASH, timestamp: 0 }. */
  readonly from?: ChainPosition;
  /** If set, the chain must end exactly here. This is what detects truncation and rewrites. */
  readonly expectedHead?: ChainHead;
};

export type ChainVerifyResult =
  | {
      ok: true;
      count: number;
      /** Seq of the last record, or null for an empty chain from genesis. */
      headSeq: number | null;
      headHash: string | null;
    }
  | {
      ok: false;
      /** Index into `records`. -1 for bad options; records.length for a head mismatch. */
      index: number;
      seq?: number;
      code: ChainErrorCode;
      message: string;
    };

const Position = z
  .object({
    seq: z.number().int().nonnegative(),
    prevHash: Sha256Hash,
    timestamp: EpochMs,
  })
  .strict();

const Head = z
  .object({
    seq: z.number().int().nonnegative(),
    hash: Sha256Hash,
  })
  .strict();

const Options = z
  .object({
    engagementId: Id,
    from: Position.optional(),
    expectedHead: Head.optional(),
  })
  .strict();

/**
 * SHA-256 over the format tag plus the canonical JSON of EVERY field except
 * `hash`. Hashing everything but `hash` (not an allowlist) means a field added
 * to the record schema later is covered automatically instead of silently
 * becoming tamperable.
 *
 * Throws CanonicalError if the record holds a value that can't be serialized
 * unambiguously. Records that passed AuditRecord validation never do.
 */
export function computeRecordHash(record: UnsignedRecord): string {
  const hashable: Record<string, unknown> = { ...record };
  delete hashable.hash;
  return sha256Hex(FORMAT_TAG + canonicalJson(hashable));
}

/**
 * Turns a caller-supplied event into a complete, hash-chained record.
 * Throws a ZodError if the event or the metadata is malformed (a programmer
 * error: log.append must catch it), and a CanonicalError if the payload holds
 * a value that can't be hashed. Does not mutate its input.
 */
export function buildRecord(
  event: AuditEvent,
  meta: { seq: number; prevHash: string; timestamp: number },
): AuditRecord {
  const parsed = AuditEvent.parse(event);
  const unsigned: UnsignedRecord = {
    ...parsed,
    seq: meta.seq,
    prevHash: meta.prevHash,
    timestamp: meta.timestamp,
  };
  return AuditRecord.parse({ ...unsigned, hash: computeRecordHash(unsigned) });
}

function fail(
  index: number,
  code: ChainErrorCode,
  message: string,
  seq?: number,
): ChainVerifyResult {
  return seq === undefined
    ? { ok: false, index, code, message }
    : { ok: false, index, seq, code, message };
}

/** Where a validation failed, never the offending value. */
function firstIssue(error: z.ZodError): string {
  const path = error.issues[0]?.path.map(String).join('.');
  return path === undefined || path === '' ? '(root)' : path;
}

/**
 * Verifies a run of records. `records` is untrusted (it comes from a database),
 * so every record is re-parsed against the schema.
 *
 * Per record, in this order: schema, engagement, seq, prevHash link,
 * non-decreasing timestamp, then the hash. The first failure is returned.
 *
 * What this can and cannot detect:
 * - It detects edits, reordering, gaps, duplicates and foreign-engagement
 *   records anywhere in the run.
 * - It cannot detect removal of the tail, or a chain someone fully rewrote and
 *   re-hashed, because every link in the new chain is internally consistent.
 *   Pass `expectedHead` (an externally anchored copy of the head) to catch both.
 * - To verify in pages, pass `from` as { seq, prevHash, timestamp } taken from
 *   the last record of the previous page.
 */
export function verifyChain(
  records: readonly unknown[],
  options: VerifyOptions,
): ChainVerifyResult {
  const opts = Options.safeParse(options);
  if (!opts.success) {
    return fail(-1, 'INVALID_OPTIONS', `Invalid options: ${firstIssue(opts.error)}`);
  }
  if (!Array.isArray(records)) {
    return fail(-1, 'INVALID_OPTIONS', 'records must be an array');
  }

  const { engagementId, expectedHead } = opts.data;
  const from = opts.data.from ?? {
    seq: 0,
    prevHash: GENESIS_PREV_HASH,
    timestamp: 0,
  };
  if (from.seq === 0 && from.prevHash !== GENESIS_PREV_HASH) {
    return fail(-1, 'INVALID_OPTIONS', 'seq 0 must start from the genesis prevHash');
  }
  if (from.seq > 0 && from.prevHash === GENESIS_PREV_HASH) {
    return fail(-1, 'INVALID_OPTIONS', 'a non-genesis position cannot use the genesis prevHash');
  }

  let expectedPrevHash = from.prevHash;
  let prevTimestamp = from.timestamp;

  for (let i = 0; i < records.length; i++) {
    const parsed = AuditRecord.safeParse(records[i]);
    if (!parsed.success) {
      return fail(
        i,
        'INVALID_RECORD',
        `Record at index ${i} failed schema validation (${firstIssue(parsed.error)})`,
      );
    }
    const record = parsed.data;
    const expectedSeq = from.seq + i;

    if (record.engagementId !== engagementId) {
      return fail(
        i,
        'ENGAGEMENT_MISMATCH',
        `Record at seq ${record.seq} belongs to engagement ${show(record.engagementId)}, expected ${show(engagementId)}`,
        record.seq,
      );
    }
    if (record.seq !== expectedSeq) {
      return fail(
        i,
        'SEQ_MISMATCH',
        `Expected seq ${expectedSeq}, got ${record.seq}`,
        record.seq,
      );
    }
    if (record.prevHash !== expectedPrevHash) {
      return fail(
        i,
        'PREV_HASH_MISMATCH',
        `prevHash mismatch at seq ${record.seq}`,
        record.seq,
      );
    }
    if (record.timestamp < prevTimestamp) {
      return fail(
        i,
        'TIMESTAMP_REGRESSION',
        `Timestamp ${record.timestamp} is earlier than ${prevTimestamp} at seq ${record.seq}`,
        record.seq,
      );
    }

    let expectedHash: string;
    try {
      expectedHash = computeRecordHash(record);
    } catch {
      return fail(i, 'INVALID_RECORD', `Record at seq ${record.seq} is not hashable`, record.seq);
    }
    if (record.hash !== expectedHash) {
      return fail(i, 'HASH_MISMATCH', `Hash mismatch at seq ${record.seq}`, record.seq);
    }

    expectedPrevHash = record.hash;
    prevTimestamp = record.timestamp;
  }

  const empty = from.seq === 0 && records.length === 0;
  const head = empty
    ? null
    : { seq: from.seq + records.length - 1, hash: expectedPrevHash };

  if (expectedHead !== undefined) {
    if (head === null) {
      return fail(records.length, 'HEAD_MISMATCH', 'Chain is empty but a head was expected');
    }
    if (head.seq !== expectedHead.seq) {
      return fail(
        records.length,
        'HEAD_MISMATCH',
        `Chain ends at seq ${head.seq}, expected ${expectedHead.seq} (records removed or added at the tail)`,
        head.seq,
      );
    }
    if (head.hash !== expectedHead.hash) {
      return fail(
        records.length,
        'HEAD_MISMATCH',
        `Head hash differs at seq ${head.seq}`,
        head.seq,
      );
    }
  }

  return {
    ok: true,
    count: records.length,
    headSeq: head === null ? null : head.seq,
    headHash: head === null ? null : head.hash,
  };
}