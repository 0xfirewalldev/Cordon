import { describe, expect, it } from 'vitest';
import { createAuditApprovals } from '../approvals';
import {
  ALICE,
  BOB,
  ENG,
  WORKER,
  approve,
  approvedEvent,
  arrayStore,
  createdEvent,
  makeScope,
  mustAppend,
  newLog,
  widerScope,
} from './helpers';

const latest = (log: ReturnType<typeof newLog>, engagementId = ENG) =>
  createAuditApprovals(log).latestApprovedHash(engagementId);

describe('latestApprovedHash: what counts as an approval', () => {
  it('is null for an engagement with no records', async () => {
    expect(await latest(newLog())).toBeNull();
  });

  it('is null when a version was created but never approved', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, ALICE));
    expect(await latest(log)).toBeNull();
  });

  it('is the hash once a different user approves it', async () => {
    const log = newLog();
    const scope = makeScope();
    await approve(log, scope);
    expect(await latest(log)).toBe(scope.hash);
  });

  it('ignores a self-approval (creator approves their own version)', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, ALICE));
    await mustAppend(log, approvedEvent(scope, ALICE));
    expect(await latest(log)).toBeNull();
  });

  it('ignores an approval by a service or the system', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, ALICE));
    await mustAppend(log, approvedEvent(scope, WORKER));
    await mustAppend(
      log,
      approvedEvent(scope, { kind: 'system', id: 'scope-guard' })
    );
    expect(await latest(log)).toBeNull();
  });

  it('accepts a version created by a service and approved by a user', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, WORKER));
    await mustAppend(log, approvedEvent(scope, ALICE));
    expect(await latest(log)).toBe(scope.hash);
  });

  it('ignores an approval with no creation record', async () => {
    const log = newLog();
    await mustAppend(log, approvedEvent(makeScope(), BOB));
    expect(await latest(log)).toBeNull();
  });

  it('ignores an approval whose scopeVersionId does not match the creation', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, ALICE));
    const forged = approvedEvent(scope, BOB);
    if (forged.type === 'scope_version_approved')
      forged.payload = { ...forged.payload, scopeVersionId: 'sv-other' };
    await mustAppend(log, forged);
    expect(await latest(log)).toBeNull();
  });

  it('a later duplicate creation cannot replace the creator', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, ALICE));
    await mustAppend(log, createdEvent(scope, BOB)); // attempt to become the creator
    await mustAppend(log, approvedEvent(scope, ALICE)); // alice approving her own version
    expect(await latest(log)).toBeNull();
  });

  it('only counts records of the requested engagement', async () => {
    const log = newLog();
    await approve(log, makeScope());
    expect(await latest(log, 'eng-2')).toBeNull();
  });
});

describe('latestApprovedHash: which version is current', () => {
  it('a newer approval supersedes the older one', async () => {
    const log = newLog();
    const v1 = makeScope();
    const v2 = widerScope();
    await approve(log, v1);
    await approve(log, v2);
    expect(await latest(log)).toBe(v2.hash);
  });

  it('re-approving an older version makes it current again', async () => {
    const log = newLog();
    const v1 = makeScope();
    const v2 = widerScope();
    await approve(log, v1);
    await approve(log, v2);
    await mustAppend(log, approvedEvent(v1, BOB));
    expect(await latest(log)).toBe(v1.hash);
  });

  it('an unapproved newer version does not displace the approved one', async () => {
    const log = newLog();
    const v1 = makeScope();
    await approve(log, v1);
    await mustAppend(log, createdEvent(widerScope(), ALICE));
    expect(await latest(log)).toBe(v1.hash);
  });
});

describe('latestApprovedHash: incremental reading', () => {
  it('reads only new records on later calls and sees new approvals', async () => {
    const { store, listCalls } = arrayStore();
    const log = newLog(store);
    const approvals = createAuditApprovals(log);
    const v1 = makeScope();
    await approve(log, v1);

    expect(await approvals.latestApprovedHash(ENG)).toBe(v1.hash);
    const afterFirst = listCalls.length;
    expect(listCalls.slice(0, afterFirst)[0]).toBe(0);

    const v2 = widerScope();
    await approve(log, v2);
    expect(await approvals.latestApprovedHash(ENG)).toBe(v2.hash);
    // the second call starts after the 2 records already read, never from 0 again
    expect(listCalls.slice(afterFirst)[0]).toBe(2);
  });

  it('pages through chains longer than one page', async () => {
    const log = newLog();
    for (let i = 0; i < 520; i++) {
      await mustAppend(log, {
        engagementId: ENG,
        actor: WORKER,
        type: 'run_finished',
        payload: { runId: `run-${i}`, status: 'succeeded' },
      });
    }
    const scope = makeScope();
    await approve(log, scope);
    expect(await latest(log)).toBe(scope.hash);
  });
});

describe('latestApprovedHash: integrity (fails closed by throwing)', () => {
  it('throws when the chain was truncated after it was read', async () => {
    const { store, records } = arrayStore();
    const log = newLog(store);
    const approvals = createAuditApprovals(log);
    const scope = makeScope();
    await approve(log, scope);
    expect(await approvals.latestApprovedHash(ENG)).toBe(scope.hash);

    records.pop(); // the approval disappears
    await expect(approvals.latestApprovedHash(ENG)).rejects.toThrow();
  });

  it('throws when the last record was replaced after it was read', async () => {
    const { store, records } = arrayStore();
    const log = newLog(store);
    const approvals = createAuditApprovals(log);
    await approve(log, makeScope());
    await approvals.latestApprovedHash(ENG);

    const last = records[records.length - 1]!;
    records[records.length - 1] = { ...last, hash: 'f'.repeat(64) };
    await expect(approvals.latestApprovedHash(ENG)).rejects.toThrow();
  });

  it('throws when the whole chain vanished after it was read', async () => {
    const { store, records } = arrayStore();
    const log = newLog(store);
    const approvals = createAuditApprovals(log);
    await approve(log, makeScope());
    await approvals.latestApprovedHash(ENG);
    records.length = 0;
    await expect(approvals.latestApprovedHash(ENG)).rejects.toThrow();
  });

  it('throws on a chain that fails verification', async () => {
    const { store, records } = arrayStore();
    const log = newLog(store);
    await approve(log, makeScope());
    const second = records[1]!;
    records[1] = { ...second, actor: { kind: 'user', id: 'mallory' } }; // edited, not re-hashed
    await expect(
      createAuditApprovals(log).latestApprovedHash(ENG)
    ).rejects.toThrow(/verification/);
  });

  it('throws when the store fails, with a fixed message', async () => {
    const approvals = createAuditApprovals({
      list: async () => {
        throw new Error('connection string: postgres://secret');
      },
      head: async () => null,
    });
    const error = await approvals
      .latestApprovedHash(ENG)
      .catch((e: Error) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).not.toContain('secret');
  });

  it('keeps working after a failure once the problem is gone', async () => {
    let fail = true;
    const { store } = arrayStore();
    const log = newLog(store);
    const scope = makeScope();
    await approve(log, scope);
    const flaky = {
      head: log.head,
      list: (...args: Parameters<typeof log.list>) =>
        fail ? Promise.reject(new Error('down')) : log.list(...args),
    };
    const approvals = createAuditApprovals(flaky);
    await expect(approvals.latestApprovedHash(ENG)).rejects.toThrow();
    fail = false;
    expect(await approvals.latestApprovedHash(ENG)).toBe(scope.hash);
  });
});
