import { canonicalJson, sha256Hex } from '@scope-guard/canonical';
import { describe, expect, it } from 'vitest';
import {
  buildRecord,
  computeRecordHash,
  GENESIS_PREV_HASH,
  verifyChain,
} from '../chain';
import type { UnsignedRecord, VerifyOptions } from '../chain';
import { AuditRecord } from '../types';
import type { AuditEvent } from '../types';

const ENG = 'eng-1';

const event = (
  i: number,
  engagementId: string,
  status: 'succeeded' | 'failed' = 'succeeded',
): AuditEvent => ({
  engagementId,
  actor: { kind: 'service', id: 'worker-1' },
  type: 'run_finished',
  payload: { runId: `run-${i}`, status },
});

function chain(
  n: number,
  o: {
    engagementId?: string;
    timestamps?: readonly number[];
    failedAt?: number;
  } = {},
): AuditRecord[] {
  const out: AuditRecord[] = [];
  let prevHash = GENESIS_PREV_HASH;
  for (let i = 0; i < n; i++) {
    const record = buildRecord(
      event(i, o.engagementId ?? ENG, i === o.failedAt ? 'failed' : 'succeeded'),
      { seq: i, prevHash, timestamp: o.timestamps?.[i] ?? 1000 + i },
    );
    out.push(record);
    prevHash = record.hash;
  }
  return out;
}

const verify = (records: readonly unknown[], extra: Partial<VerifyOptions> = {}) =>
  verifyChain(records, { engagementId: ENG, ...extra });

/** A copy with `patch` applied to one record, deliberately NOT re-hashed. */
const patch = (
  records: readonly AuditRecord[],
  index: number,
  changes: Record<string, unknown>,
): unknown[] => records.map((r, k) => (k === index ? { ...r, ...changes } : r));

describe('computeRecordHash', () => {
  const fixed: UnsignedRecord = {
    engagementId: 'eng-1',
    actor: { kind: 'user', id: 'u-1' },
    type: 'run_finished',
    payload: { runId: 'run-1', status: 'succeeded' },
    seq: 0,
    timestamp: 1000,
    prevHash: GENESIS_PREV_HASH,
  };
  const canonical = `{"actor":{"id":"u-1","kind":"user"},"engagementId":"eng-1","payload":{"runId":"run-1","status":"succeeded"},"prevHash":"${GENESIS_PREV_HASH}","seq":0,"timestamp":1000,"type":"run_finished"}`;

  it('pins the format: tag, then canonical JSON of every field except hash', () => {
    expect(canonicalJson(fixed)).toBe(canonical);
    expect(computeRecordHash(fixed)).toBe(
      sha256Hex(`scope-guard.audit.v1\n${canonical}`),
    );
    // After the first green run, also paste the digest here as a literal, so a
    // change to the format can never go unnoticed.
  });

  it('is deterministic, and independent of key order', () => {
    const reordered = {
      payload: { status: 'succeeded', runId: 'run-1' },
      type: 'run_finished',
      prevHash: GENESIS_PREV_HASH,
      timestamp: 1000,
      seq: 0,
      actor: { id: 'u-1', kind: 'user' },
      engagementId: 'eng-1',
    } as UnsignedRecord;
    expect(computeRecordHash(reordered)).toBe(computeRecordHash(fixed));
    expect(computeRecordHash(fixed)).toBe(computeRecordHash(fixed));
  });

  it('ignores a hash field if one is present', () => {
    const withHash = { ...fixed, hash: 'f'.repeat(64) } as UnsignedRecord;
    expect(computeRecordHash(withHash)).toBe(computeRecordHash(fixed));
  });

  it.each([
    ['engagementId', { engagementId: 'eng-2' }],
    ['seq', { seq: 1 }],
    ['prevHash', { prevHash: 'c'.repeat(64) }],
    ['timestamp', { timestamp: 1001 }],
    ['actor id', { actor: { kind: 'user', id: 'u-2' } }],
    ['actor kind', { actor: { kind: 'service', id: 'u-1' } }],
    ['type', { type: 'auth_failure' }],
    ['payload value', { payload: { runId: 'run-1', status: 'failed' } }],
    ['payload extra key', { payload: { runId: 'run-1', status: 'succeeded', x: 1 } }],
  ])('changes when %s changes', (_label, change) => {
    const changed = { ...fixed, ...change } as UnsignedRecord;
    expect(computeRecordHash(changed)).not.toBe(computeRecordHash(fixed));
  });

  it('does not mutate its input', () => {
    const before = structuredClone(fixed);
    computeRecordHash(fixed);
    expect(fixed).toStrictEqual(before);
  });
});

describe('buildRecord', () => {
  it('produces a schema-valid record that verifies', () => {
    const [record] = chain(1);
    expect(AuditRecord.safeParse(record).success).toBe(true);
    expect(verify([record])).toMatchObject({ ok: true, count: 1 });
  });

  it('links each record to the previous one', () => {
    const [first, second] = chain(2);
    expect(first!.prevHash).toBe(GENESIS_PREV_HASH);
    expect(second!.prevHash).toBe(first!.hash);
  });

  it('does not mutate the event', () => {
    const input = event(0, ENG);
    const before = structuredClone(input);
    buildRecord(input, { seq: 0, prevHash: GENESIS_PREV_HASH, timestamp: 1000 });
    expect(input).toStrictEqual(before);
  });

  it('rejects malformed events', () => {
    const meta = { seq: 0, prevHash: GENESIS_PREV_HASH, timestamp: 1000 };
    const bad: unknown[] = [
      { ...event(0, ENG), payload: {} },
      { ...event(0, ENG), hash: 'a'.repeat(64) },
      { ...event(0, ENG), seq: 0 },
      { ...event(0, ENG), actor: 'alice' },
      { ...event(0, ENG), type: 'nope' },
      null,
    ];
    for (const e of bad) {
      expect(() => buildRecord(e as AuditEvent, meta)).toThrow();
    }
  });

  it.each([
    ['a negative seq', { seq: -1, prevHash: GENESIS_PREV_HASH, timestamp: 1 }],
    ['a fractional seq', { seq: 1.5, prevHash: GENESIS_PREV_HASH, timestamp: 1 }],
    ['a bad prevHash', { seq: 0, prevHash: 'x', timestamp: 1 }],
    ['a negative timestamp', { seq: 0, prevHash: GENESIS_PREV_HASH, timestamp: -1 }],
    ['a NaN timestamp', { seq: 0, prevHash: GENESIS_PREV_HASH, timestamp: Number.NaN }],
  ])('rejects metadata with %s', (_label, meta) => {
    expect(() => buildRecord(event(0, ENG), meta)).toThrow();
  });
});

describe('verifyChain: valid chains', () => {
  it('accepts an empty chain from genesis', () => {
    expect(verify([])).toStrictEqual({
      ok: true,
      count: 0,
      headSeq: null,
      headHash: null,
    });
  });

  it('accepts a chain and reports its head', () => {
    const records = chain(5);
    expect(verify(records)).toStrictEqual({
      ok: true,
      count: 5,
      headSeq: 4,
      headHash: records[4]!.hash,
    });
  });

  it('accepts equal timestamps', () => {
    expect(verify(chain(3, { timestamps: [1000, 1000, 1000] })).ok).toBe(true);
  });

  it('accepts frozen input and does not mutate it', () => {
    const records = Object.freeze(chain(3).map((r) => Object.freeze({ ...r })));
    expect(verifyChain(records, { engagementId: ENG }).ok).toBe(true);
  });
});

describe('verifyChain: tampering', () => {
  const records = chain(5);

  it.each([
    ['payload', { payload: { runId: 'run-2', status: 'failed' } }],
    ['actor', { actor: { kind: 'user', id: 'someone-else' } }],
    ['timestamp', { timestamp: 1003 }],
    ['hash', { hash: 'f'.repeat(64) }],
  ])('detects an edited %s', (_label, change) => {
    expect(verify(patch(records, 2, change))).toMatchObject({
      ok: false,
      code: 'HASH_MISMATCH',
      index: 2,
      seq: 2,
    });
  });

  it('detects a changed prevHash', () => {
    expect(verify(patch(records, 3, { prevHash: 'b'.repeat(64) }))).toMatchObject({
      ok: false,
      code: 'PREV_HASH_MISMATCH',
      index: 3,
    });
  });

  it('detects a changed seq', () => {
    expect(verify(patch(records, 2, { seq: 7 }))).toMatchObject({
      ok: false,
      code: 'SEQ_MISMATCH',
      index: 2,
      seq: 7,
    });
  });

  it('detects a changed engagementId', () => {
    expect(verify(patch(records, 2, { engagementId: 'eng-2' }))).toMatchObject({
      ok: false,
      code: 'ENGAGEMENT_MISMATCH',
      index: 2,
    });
  });

  it('detects a type changed to one that no longer fits the payload', () => {
    expect(verify(patch(records, 2, { type: 'auth_failure' }))).toMatchObject({
      ok: false,
      code: 'INVALID_RECORD',
      index: 2,
    });
  });

  it('detects a deleted middle record', () => {
    const gap = [...records.slice(0, 2), ...records.slice(3)];
    expect(verify(gap)).toMatchObject({ ok: false, code: 'SEQ_MISMATCH', index: 2 });
  });

  it('detects swapped records', () => {
    const swapped = [records[0], records[2], records[1], records[3], records[4]];
    expect(verify(swapped)).toMatchObject({ ok: false, code: 'SEQ_MISMATCH', index: 1 });
  });

  it('detects a duplicated record', () => {
    expect(verify([records[0], records[0]])).toMatchObject({
      ok: false,
      code: 'SEQ_MISMATCH',
      index: 1,
    });
  });

  it('detects a wrong genesis prevHash even when the hash is consistent', () => {
    const unsigned: UnsignedRecord = {
      ...event(0, ENG),
      seq: 0,
      prevHash: 'b'.repeat(64),
      timestamp: 1000,
    };
    const bad = AuditRecord.parse({ ...unsigned, hash: computeRecordHash(unsigned) });
    expect(verify([bad])).toMatchObject({
      ok: false,
      code: 'PREV_HASH_MISMATCH',
      index: 0,
    });
  });

  it('detects timestamps going backwards even when hashes are consistent', () => {
    const regressed = chain(3, { timestamps: [1000, 900, 1100] });
    expect(verify(regressed)).toMatchObject({
      ok: false,
      code: 'TIMESTAMP_REGRESSION',
      index: 1,
    });
  });
});

describe('verifyChain: engagement binding', () => {
  it('rejects a complete, valid chain that belongs to another engagement', () => {
    const other = chain(3, { engagementId: 'eng-2' });
    expect(verifyChain(other, { engagementId: 'eng-2' }).ok).toBe(true);
    expect(verify(other)).toMatchObject({
      ok: false,
      code: 'ENGAGEMENT_MISMATCH',
      index: 0,
    });
  });

  it('rejects a foreign record spliced into the middle', () => {
    const mine = chain(5);
    const foreign = chain(5, { engagementId: 'eng-2' });
    const spliced = [mine[0], mine[1], foreign[2], mine[3], mine[4]];
    expect(verify(spliced)).toMatchObject({
      ok: false,
      code: 'ENGAGEMENT_MISMATCH',
      index: 2,
    });
  });

  it('escapes the engagement id it reports', () => {
    const other = chain(1, { engagementId: 'eng\n2' });
    const result = verify(other);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).not.toMatch(/\n/);
  });
});

describe('verifyChain: the anchored head', () => {
  const records = chain(5);
  const head = { seq: 4, hash: records[4]!.hash };

  it('accepts the full chain against its head', () => {
    expect(verify(records, { expectedHead: head }).ok).toBe(true);
  });

  it('a truncated tail passes on its own but fails against the head', () => {
    const truncated = records.slice(0, 3);
    expect(verify(truncated).ok).toBe(true);
    expect(verify(truncated, { expectedHead: head })).toMatchObject({
      ok: false,
      code: 'HEAD_MISMATCH',
      index: 3,
    });
  });

  it('a chain longer than the head fails', () => {
    const longer = chain(6);
    expect(verify(longer, { expectedHead: head })).toMatchObject({
      ok: false,
      code: 'HEAD_MISMATCH',
    });
  });

  it('a fully rewritten and re-hashed chain passes alone but fails against the head', () => {
    const rewritten = chain(5, { failedAt: 2 });
    expect(verify(rewritten).ok).toBe(true);
    expect(verify(rewritten, { expectedHead: head })).toMatchObject({
      ok: false,
      code: 'HEAD_MISMATCH',
      seq: 4,
    });
  });

  it('an empty chain fails when a head was expected', () => {
    expect(verify([], { expectedHead: head })).toMatchObject({
      ok: false,
      code: 'HEAD_MISMATCH',
    });
  });
});

describe('verifyChain: resuming from a checkpoint', () => {
  const records = chain(5);
  const checkpoint = {
    seq: 3,
    prevHash: records[2]!.hash,
    timestamp: records[2]!.timestamp,
  };

  it('verifies the second page from the last record of the first', () => {
    expect(verify(records.slice(3), { from: checkpoint })).toStrictEqual({
      ok: true,
      count: 2,
      headSeq: 4,
      headHash: records[4]!.hash,
    });
  });

  it('verifies the second page against the anchored head', () => {
    const head = { seq: 4, hash: records[4]!.hash };
    expect(verify(records.slice(3), { from: checkpoint, expectedHead: head }).ok).toBe(true);
  });

  it('rejects a wrong checkpoint prevHash, seq or timestamp', () => {
    const page = records.slice(3);
    expect(verify(page, { from: { ...checkpoint, prevHash: 'b'.repeat(64) } })).toMatchObject({
      ok: false,
      code: 'PREV_HASH_MISMATCH',
      index: 0,
    });
    expect(verify(page, { from: { ...checkpoint, seq: 2 } })).toMatchObject({
      ok: false,
      code: 'SEQ_MISMATCH',
      index: 0,
    });
    expect(verify(page, { from: { ...checkpoint, timestamp: 5000 } })).toMatchObject({
      ok: false,
      code: 'TIMESTAMP_REGRESSION',
      index: 0,
    });
  });

  it('an empty page at a checkpoint reports the checkpoint as the head', () => {
    const head = { seq: 2, hash: records[2]!.hash };
    expect(verify([], { from: checkpoint })).toStrictEqual({
      ok: true,
      count: 0,
      headSeq: 2,
      headHash: records[2]!.hash,
    });
    expect(verify([], { from: checkpoint, expectedHead: head }).ok).toBe(true);
  });
});

describe('verifyChain: invalid options', () => {
  const run = (opts: unknown, recs: readonly unknown[] = chain(2)) =>
    verifyChain(recs, opts as VerifyOptions);

  it.each([
    ['no options', undefined],
    ['an empty engagementId', { engagementId: '' }],
    ['a missing engagementId', {}],
    ['an unknown option', { engagementId: ENG, extra: true }],
    ['a negative from.seq', { engagementId: ENG, from: { seq: -1, prevHash: GENESIS_PREV_HASH, timestamp: 0 } }],
    ['a fractional from.seq', { engagementId: ENG, from: { seq: 1.5, prevHash: 'b'.repeat(64), timestamp: 0 } }],
    ['a bad from.prevHash', { engagementId: ENG, from: { seq: 1, prevHash: 'x', timestamp: 0 } }],
    ['seq 0 with a non-genesis prevHash', { engagementId: ENG, from: { seq: 0, prevHash: 'b'.repeat(64), timestamp: 0 } }],
    ['seq > 0 with the genesis prevHash', { engagementId: ENG, from: { seq: 3, prevHash: GENESIS_PREV_HASH, timestamp: 0 } }],
    ['a bad expectedHead hash', { engagementId: ENG, expectedHead: { seq: 1, hash: 'X' } }],
    ['a fractional expectedHead seq', { engagementId: ENG, expectedHead: { seq: 1.5, hash: 'a'.repeat(64) } }],
  ])('rejects %s', (_label, opts) => {
    expect(run(opts)).toMatchObject({ ok: false, code: 'INVALID_OPTIONS', index: -1 });
  });

  it('rejects records that are not an array', () => {
    expect(run({ engagementId: ENG }, null as never)).toMatchObject({
      ok: false,
      code: 'INVALID_OPTIONS',
    });
  });
});

describe('verifyChain: untrusted records', () => {
  it.each([[null], [42], ['x'], [{}], [[]], [undefined]])(
    'rejects a non-record entry %j',
    (entry) => {
      expect(verify([entry])).toMatchObject({
        ok: false,
        code: 'INVALID_RECORD',
        index: 0,
      });
    },
  );

  it.each([
    ['an extra key', { extra: true }],
    ['a missing hash', { hash: undefined }],
    ['an uppercase hash', { hash: 'A'.repeat(64) }],
    ['a fractional timestamp', { timestamp: 1.5 }],
    ['a string actor', { actor: 'alice' }],
  ])('rejects a record with %s', (_label, change) => {
    expect(verify(patch(chain(3), 1, change))).toMatchObject({
      ok: false,
      code: 'INVALID_RECORD',
      index: 1,
    });
  });

  it('reports where a record is invalid but never what it contained', () => {
    const records = chain(2);
    const result = verify(
      patch(records, 0, { actor: { kind: 'user', id: 'SECRET-MARKER', extra: 1 } }),
    );
    expect(result).toMatchObject({ ok: false, code: 'INVALID_RECORD' });
    if (!result.ok) expect(result.message).not.toContain('SECRET-MARKER');
  });
});