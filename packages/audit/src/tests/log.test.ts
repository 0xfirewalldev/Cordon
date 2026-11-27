import { describe, expect, it } from 'vitest';
import {
  makeAuthFailureEvent,
  makeDecisionEvent,
  makeRunFinishedEvent,
  makeRunStartedEvent,
  makeStatusChangedEvent,
  SAMPLE_ENGAGEMENT_ID,
  SAMPLE_HASH,
} from '../__fixtures__/event';
import { GENESIS_PREV_HASH } from '../chain';
import { createAuditLog } from '../log';
import { createMemoryStore, InMemoryAuditStore } from '../memory-store';
import { SequenceConflictError, type AuditStore } from '../store';
import { AuditRecord, type AuditEvent } from '../types';

describe('InMemoryAuditStore', () => {
  it('returns null head and empty list for an unknown engagement', async () => {
    const store = createMemoryStore();
    expect(await store.head('eng-missing')).toBeNull();
    expect(await store.list('eng-missing')).toEqual([]);
  });

  it('rejects out-of-order seq and mismatched prevHash on append', async () => {
    const store = createMemoryStore();
    const log = createAuditLog({ store, now: () => 1000 });
    const first = await log.append(makeRunStartedEvent('r-1'));
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    await expect(
      store.append({ ...first.record, seq: 2 }),
    ).rejects.toThrow(/Sequence conflict/);

    await expect(
      store.append({
        ...first.record,
        seq: 1,
        prevHash: 'f'.repeat(64),
      }),
    ).rejects.toThrow(/prevHash mismatch/);
  });

  it('supports pagination via fromSeq and limit without exposing mutable internals', async () => {
    const store = createMemoryStore();
    let tick = 1000;
    const log = createAuditLog({ store, now: () => (tick += 10) });

    for (let i = 0; i < 5; i++) {
      const res = await log.append(makeRunFinishedEvent(`run-${i}`));
      expect(res.ok).toBe(true);
    }

    const page1 = await store.list(SAMPLE_ENGAGEMENT_ID, { fromSeq: 1, limit: 2 });
    expect(page1.map((r) => r.seq)).toEqual([1, 2]);

    // Mutating returned object does not mutate stored record
    (page1[0] as { actor: { id: string } }).actor.id = 'tampered';
    const reread = await store.list(SAMPLE_ENGAGEMENT_ID, { fromSeq: 1, limit: 1 });
    expect(reread[0]?.actor.id).toBe('scanner-worker-1');

    expect(await store.list(SAMPLE_ENGAGEMENT_ID, { fromSeq: 10 })).toEqual([]);
    expect(await store.list(SAMPLE_ENGAGEMENT_ID, { limit: 0 })).toEqual([]);
  });
});

describe('createAuditLog', () => {
  it('appends a genesis record and chains subsequent records with injected clock', async () => {
    let time = 5000;
    const log = createAuditLog({
      store: createMemoryStore(),
      now: () => (time += 100),
    });

    const r0 = await log.append(makeStatusChangedEvent());
    const r1 = await log.append(makeDecisionEvent());
    const r2 = await log.append(makeRunStartedEvent('run-1'));

    expect(r0.ok && r1.ok && r2.ok).toBe(true);
    if (!r0.ok || !r1.ok || !r2.ok) return;

    expect(r0.record.seq).toBe(0);
    expect(r0.record.prevHash).toBe(GENESIS_PREV_HASH);
    expect(r0.record.timestamp).toBe(5100);

    expect(r1.record.seq).toBe(1);
    expect(r1.record.prevHash).toBe(r0.record.hash);
    expect(r1.record.timestamp).toBe(5200);

    expect(r2.record.seq).toBe(2);
    expect(r2.record.prevHash).toBe(r1.record.hash);
    expect(r2.record.timestamp).toBe(5300);

    const head = await log.head(SAMPLE_ENGAGEMENT_ID);
    expect(head).toEqual(r2.record);

    const verification = await log.verify(SAMPLE_ENGAGEMENT_ID, {
      expectedHead: { seq: r2.record.seq, hash: r2.record.hash },
    });
    expect(verification).toEqual({
      ok: true,
      count: 3,
      headSeq: 2,
      headHash: r2.record.hash,
    });
  });

  it('isolates chains across different engagements', async () => {
    const log = createAuditLog({
      store: createMemoryStore(),
      now: () => 2000,
    });

    const a = await log.append(makeRunStartedEvent('r-a', 'eng-a'));
    const b = await log.append(makeRunStartedEvent('r-b', 'eng-b'));
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;

    expect(a.record.seq).toBe(0);
    expect(b.record.seq).toBe(0);
    expect(a.record.prevHash).toBe(GENESIS_PREV_HASH);
    expect(b.record.prevHash).toBe(GENESIS_PREV_HASH);

    expect((await log.verify('eng-a')).ok).toBe(true);
    expect((await log.verify('eng-b')).ok).toBe(true);
  });

  it('serializes concurrent appends for the same engagement without seq races', async () => {
    let tick = 1000;
    const baseStore = new InMemoryAuditStore();
    // Introduce an async delay on head() to force interleaving if unserialized
    const slowStore: AuditStore = {
      async head(id) {
        await new Promise((r) => setTimeout(r, 5));
        return baseStore.head(id);
      },
      append: (r) => baseStore.append(r),
      list: (id, opts) => baseStore.list(id, opts),
    };

    const log = createAuditLog({ store: slowStore, now: () => (tick += 1) });
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        log.append(makeRunFinishedEvent(`run-${i}`)),
      ),
    );

    expect(results.every((r) => r.ok)).toBe(true);
    const seqs = results.map((r) => (r.ok ? r.record.seq : -1));
    expect(seqs).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);

    const verified = await log.verify(SAMPLE_ENGAGEMENT_ID);
    expect(verified).toMatchObject({ ok: true, count: 8, headSeq: 7 });
  });

  it('two createAuditLog instances sharing one store both succeed with contiguous seqs', async () => {
    // Simulates a cross-process write race handled by SequenceConflictError retries.
    let tick = 1000;
    const baseStore = new InMemoryAuditStore();

    // Add a delay so the two log instances race on head()
    const sharedStore: AuditStore = {
      async head(id) {
        await new Promise((r) => setTimeout(r, 5));
        return baseStore.head(id);
      },
      append: (r) => baseStore.append(r),
      list: (id, opts) => baseStore.list(id, opts),
    };

    const logA = createAuditLog({ store: sharedStore, now: () => (tick += 1) });
    const logB = createAuditLog({ store: sharedStore, now: () => (tick += 1) });

    // Fire appends from both instances concurrently
    const [resA, resB] = await Promise.all([
      logA.append(makeRunFinishedEvent('run-a')),
      logB.append(makeRunFinishedEvent('run-b')),
    ]);

    expect(resA.ok).toBe(true);
    expect(resB.ok).toBe(true);

    // Both records must have distinct, contiguous seqs
    if (!resA.ok || !resB.ok) return;
    const seqs = [resA.record.seq, resB.record.seq].sort((a, b) => a - b);
    expect(seqs).toEqual([0, 1]);

    // Chain verifies end-to-end
    const verified = await logA.verify(SAMPLE_ENGAGEMENT_ID);
    expect(verified).toMatchObject({ ok: true, count: 2 });
  });

  it('rejects malformed events without writing to the store', async () => {
    const store = createMemoryStore();
    const log = createAuditLog({ store, now: () => 1000 });

    const badEvent = {
      engagementId: SAMPLE_ENGAGEMENT_ID,
      actor: { kind: 'user', id: 'alice' },
      type: 'run_finished',
      payload: { runId: 'r-1', status: 'succeeded', extra: true },
    } as unknown as AuditEvent;

    const res = await log.append(badEvent);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.code).toBe('INVALID_EVENT');
    }
    expect(await log.head(SAMPLE_ENGAGEMENT_ID)).toBeNull();
  });

  it('clamps a backwards clock step to keep the chain monotonic', async () => {
    let time = 2000;
    const log = createAuditLog({
      store: createMemoryStore(),
      now: () => time,
    });

    const first = await log.append(makeAuthFailureEvent());
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    // Clock steps backwards — clamped to prev.timestamp, not rejected
    time = 1999;
    const clamped = await log.append(makeAuthFailureEvent());
    expect(clamped.ok).toBe(true);
    if (!clamped.ok) return;
    expect(clamped.record.timestamp).toBe(2000);

    // Forward clock resumes normally
    time = 3000;
    const forward = await log.append(makeAuthFailureEvent());
    expect(forward.ok).toBe(true);
    if (!forward.ok) return;
    expect(forward.record.timestamp).toBe(3000);
  });

  it('returns INVALID_TIMESTAMP when the clock returns a negative or non-integer value', async () => {
    for (const badTime of [-5, 1.5, Number.NaN]) {
      const log = createAuditLog({
        store: createMemoryStore(),
        now: () => badTime,
      });
      const res = await log.append(makeAuthFailureEvent());
      expect(res).toMatchObject({ ok: false, code: 'INVALID_TIMESTAMP' });
    }
  });

  it('returns INVALID_TIMESTAMP when the clock throws', async () => {
    const log = createAuditLog({
      store: createMemoryStore(),
      now: () => { throw new Error('clock unavailable'); },
    });
    const res = await log.append(makeAuthFailureEvent());
    expect(res).toMatchObject({ ok: false, code: 'INVALID_TIMESTAMP' });
  });

  it('returns STORE_ERROR when store.head throws in append', async () => {
    const store: AuditStore = {
      head: () => Promise.reject(new Error('db down')),
      append: () => Promise.resolve(),
      list: () => Promise.resolve([]),
    };
    const log = createAuditLog({ store, now: () => 1000 });
    const res = await log.append(makeRunFinishedEvent());
    expect(res).toMatchObject({ ok: false, code: 'STORE_ERROR' });
  });

  it("returns STORE_ERROR when the store returns another engagement's head", async () => {
    // A buggy store returns the wrong engagement's head — append must reject it.
    const store = createMemoryStore();
    const log = createAuditLog({ store, now: () => 1000 });

    // Seed a record for a different engagement so head() can return it
    const seed = await log.append(makeRunFinishedEvent('run-seed', 'succeeded', 'eng-other'));
    expect(seed.ok).toBe(true);

    const wrongEngStore: AuditStore = {
      // Always returns a head from a different engagement
      head: (_id) => store.head('eng-other'),
      append: (r) => store.append(r),
      list: (id, opts) => store.list(id, opts),
    };

    const logWrong = createAuditLog({ store: wrongEngStore, now: () => 2000 });
    const res = await logWrong.append(makeRunFinishedEvent('run-1', 'succeeded', SAMPLE_ENGAGEMENT_ID));
    expect(res).toMatchObject({ ok: false, code: 'STORE_ERROR' });
  });

  it('verifies multi-page chains and detects tampering or truncation', async () => {
    const records: AuditRecord[] = [];
    const store: AuditStore = {
      async head(id) {
        const matching = records.filter((r) => r.engagementId === id);
        return matching[matching.length - 1] ?? null;
      },
      async append(r) {
        records.push(r);
      },
      async list(id, opts = {}) {
        const matching = records.filter((r) => r.engagementId === id);
        const from = opts.fromSeq ?? 0;
        const end = opts.limit !== undefined ? from + opts.limit : undefined;
        return matching.slice(from, end);
      },
    };

    let tick = 1000;
    const log = createAuditLog({ store, now: () => (tick += 10) });

    for (let i = 0; i < 5; i++) {
      await log.append(makeRunFinishedEvent(`run-${i}`));
    }

    const head = await log.head(SAMPLE_ENGAGEMENT_ID);
    expect(head).not.toBeNull();

    // Multi-page verification (pageSize: 2 => 3 pages: 2, 2, 1)
    const okMulti = await log.verify(SAMPLE_ENGAGEMENT_ID, {
      pageSize: 2,
      expectedHead: { seq: head!.seq, hash: head!.hash },
    });
    expect(okMulti).toEqual({
      ok: true,
      count: 5,
      headSeq: 4,
      headHash: head!.hash,
    });

    // Exact multiple of pageSize (pageSize: 5 -> 1 full page, then empty page)
    const okExact = await log.verify(SAMPLE_ENGAGEMENT_ID, {
      pageSize: 5,
      expectedHead: { seq: head!.seq, hash: head!.hash },
    });
    expect(okExact).toEqual({
      ok: true,
      count: 5,
      headSeq: 4,
      headHash: head!.hash,
    });

    // Detect truncation via expectedHead
    records.pop();
    const truncated = await log.verify(SAMPLE_ENGAGEMENT_ID, {
      pageSize: 2,
      expectedHead: { seq: head!.seq, hash: head!.hash },
    });
    expect(truncated).toMatchObject({ ok: false, code: 'HEAD_MISMATCH' });

    // Detect tampering in middle page
    records[2] = {
      ...records[2]!,
      payload: { runId: 'tampered', status: 'failed' },
    } as AuditRecord;
    const tampered = await log.verify(SAMPLE_ENGAGEMENT_ID, { pageSize: 2 });
    expect(tampered).toMatchObject({
      ok: false,
      index: 2,
      seq: 2,
      code: 'HASH_MISMATCH',
    });
  });

  it('verify: a store that caps pages below pageSize still checks the whole chain', async () => {
    // Simulates a Postgres store that returns at most 2 rows even when asked for 1000.
    const records: AuditRecord[] = [];
    const cappedStore: AuditStore = {
      async head(id) {
        const matching = records.filter((r) => r.engagementId === id);
        return matching[matching.length - 1] ?? null;
      },
      async append(r) { records.push(r); },
      async list(id, opts = {}) {
        const matching = records.filter((r) => r.engagementId === id);
        const from = opts.fromSeq ?? 0;
        // Always cap at 2, regardless of what limit was requested
        const cap = 2;
        return matching.slice(from, from + cap);
      },
    };

    let tick = 1000;
    const log = createAuditLog({ store: cappedStore, now: () => (tick += 10) });

    for (let i = 0; i < 5; i++) {
      await log.append(makeRunFinishedEvent(`run-${i}`));
    }

    const head = await log.head(SAMPLE_ENGAGEMENT_ID);
    expect(head).not.toBeNull();

    // pageSize: 1000, but store caps at 2 — verify must still read all 5 records
    const result = await log.verify(SAMPLE_ENGAGEMENT_ID, {
      pageSize: 1000,
      expectedHead: { seq: head!.seq, hash: head!.hash },
    });
    expect(result).toEqual({
      ok: true,
      count: 5,
      headSeq: 4,
      headHash: head!.hash,
    });
  });

  it('verify returns STORE_ERROR when store.list throws instead of throwing', async () => {
    const store: AuditStore = {
      head: () => Promise.resolve(null),
      append: () => Promise.resolve(),
      list: () => Promise.reject(new Error('db down')),
    };
    const log = createAuditLog({ store, now: () => 1000 });
    const result = await log.verify(SAMPLE_ENGAGEMENT_ID);
    expect(result).toMatchObject({ ok: false, code: 'STORE_ERROR' });
  });

  it('returns INVALID_OPTIONS for bad engagementId or pageSize in verify', async () => {
    const log = createAuditLog({ store: createMemoryStore() });
    expect(await log.verify('')).toMatchObject({
      ok: false,
      code: 'INVALID_OPTIONS',
    });
    expect(
      await log.verify(SAMPLE_ENGAGEMENT_ID, { pageSize: 0 }),
    ).toMatchObject({
      ok: false,
      code: 'INVALID_OPTIONS',
    });
  });

  it('an empty chain fails against an expected head', async () => {
    const log = createAuditLog({ store: createMemoryStore() });
    expect(
      await log.verify(SAMPLE_ENGAGEMENT_ID, {
        expectedHead: { seq: 0, hash: SAMPLE_HASH },
      }),
    ).toMatchObject({
      ok: false,
      code: 'HEAD_MISMATCH',
    });
  });

  it('a redacted record is rejected by AuditRecord.parse and by verifyChain', async () => {
    // Import redactRecord lazily here to avoid circular dev concerns
    const { redactRecord } = await import('../redact');

    const store = createMemoryStore();
    const log = createAuditLog({ store, now: () => 1000 });
    const appended = await log.append(makeRunFinishedEvent('run-1'));
    expect(appended.ok).toBe(true);
    if (!appended.ok) return;

    const redacted = redactRecord(appended.record);

    // AuditRecord.parse must reject it (strict schema + redacted: true extra key)
    expect(AuditRecord.safeParse(redacted).success).toBe(false);

    // Attempting to push a redacted record into the store fails
    await expect(store.append(redacted as unknown as AuditRecord)).rejects.toThrow();
  });

  it('head and list reject garbage records from the store without leaking ZodError', async () => {
    const garbageStore: AuditStore = {
      head: async () => ({ garbage: true }) as unknown as AuditRecord,
      append: async () => {},
      list: async () => [{ garbage: true }] as unknown as AuditRecord[],
    };
    const log = createAuditLog({ store: garbageStore });

    await expect(log.head(SAMPLE_ENGAGEMENT_ID)).rejects.toThrow(
      'Store returned an invalid chain head',
    );
    await expect(log.list(SAMPLE_ENGAGEMENT_ID)).rejects.toThrow(
      'Store returned an invalid audit record',
    );
  });

  it("head and list reject records belonging to another engagement", async () => {
    const store = createMemoryStore();
    const log = createAuditLog({ store, now: () => 1000 });
    const seed = await log.append(
      makeRunFinishedEvent('run-seed', 'succeeded', 'eng-a'),
    );
    expect(seed.ok).toBe(true);

    const foreignStore: AuditStore = {
      head: () => store.head('eng-a'),
      append: (r) => store.append(r),
      list: (_id, opts) => store.list('eng-a', opts),
    };
    const logForeign = createAuditLog({ store: foreignStore });

    await expect(logForeign.head('eng-b')).rejects.toThrow(
      'Store returned an invalid chain head',
    );
    await expect(logForeign.list('eng-b')).rejects.toThrow(
      'Store returned an invalid audit record',
    );
  });
});
