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
import { Actor, AuditEvent, AuditRecord } from '../types';

describe('Actor', () => {
  it('accepts user, service, and system actors', () => {
    for (const kind of ['user', 'service', 'system'] as const) {
      expect(Actor.safeParse({ kind, id: 'actor-1' }).success).toBe(true);
    }
  });

  it('rejects unknown kinds, empty ids, and extra keys', () => {
    expect(Actor.safeParse({ kind: 'bot', id: 'a' }).success).toBe(false);
    expect(Actor.safeParse({ kind: 'user', id: '' }).success).toBe(false);
    expect(Actor.safeParse({ kind: 'user', id: 'a', extra: 1 }).success).toBe(
      false,
    );
  });
});

describe('AuditEvent', () => {
  it('parses all supported event variants', () => {
    const events = [
      makeDecisionEvent(),
      makeRunStartedEvent(),
      makeRunFinishedEvent(),
      makeAuthFailureEvent(),
      makeStatusChangedEvent(),
      {
        engagementId: SAMPLE_ENGAGEMENT_ID,
        actor: { kind: 'user' as const, id: 'alice' },
        type: 'scope_version_created' as const,
        payload: {
          scopeVersionId: 'sv-1',
          versionHash: SAMPLE_HASH,
          ruleCount: 3,
          notBefore: 1000,
          notAfter: 2000,
        },
      },
      {
        engagementId: SAMPLE_ENGAGEMENT_ID,
        actor: { kind: 'user' as const, id: 'bob' },
        type: 'scope_version_approved' as const,
        payload: {
          scopeVersionId: 'sv-1',
          versionHash: SAMPLE_HASH,
        },
      },
    ];

    for (const ev of events) {
      expect(AuditEvent.safeParse(ev).success).toBe(true);
    }
  });

  it('rejects caller-supplied assigned fields (seq, timestamp, prevHash, hash)', () => {
    const ev = makeRunFinishedEvent();
    expect(AuditEvent.safeParse({ ...ev, seq: 0 }).success).toBe(false);
    expect(AuditEvent.safeParse({ ...ev, timestamp: 1000 }).success).toBe(false);
    expect(
      AuditEvent.safeParse({ ...ev, prevHash: GENESIS_PREV_HASH }).success,
    ).toBe(false);
    expect(AuditEvent.safeParse({ ...ev, hash: SAMPLE_HASH }).success).toBe(
      false,
    );
  });

  it('rejects mismatched type and payload', () => {
    const ev = makeRunFinishedEvent();
    expect(
      AuditEvent.safeParse({ ...ev, type: 'auth_failure' }).success,
    ).toBe(false);
  });
});

describe('AuditRecord', () => {
  it('parses a complete record and rejects missing chain metadata', () => {
    const ev = makeRunFinishedEvent();
    expect(AuditRecord.safeParse(ev).success).toBe(false);
    expect(
      AuditRecord.safeParse({
        ...ev,
        seq: 0,
        timestamp: 1000,
        prevHash: GENESIS_PREV_HASH,
        hash: SAMPLE_HASH,
      }).success,
    ).toBe(true);
  });

  it('a valid record never parses as an event (events have no chain metadata)', () => {
    const record = {
      engagementId: SAMPLE_ENGAGEMENT_ID,
      actor: { kind: 'service' as const, id: 'worker-1' },
      type: 'run_finished' as const,
      payload: { runId: 'run-1', status: 'succeeded' as const },
      seq: 0,
      timestamp: 1000,
      prevHash: GENESIS_PREV_HASH,
      hash: SAMPLE_HASH,
    };
    // Record parses as AuditRecord
    expect(AuditRecord.safeParse(record).success).toBe(true);
    // Record does NOT parse as AuditEvent (strict: seq/timestamp/prevHash/hash are extra keys)
    expect(AuditEvent.safeParse(record).success).toBe(false);
  });

  it('a valid event never parses as a record (records require chain metadata)', () => {
    const ev = makeRunFinishedEvent();
    // Event parses as AuditEvent
    expect(AuditEvent.safeParse(ev).success).toBe(true);
    // Event does NOT parse as AuditRecord (missing seq, timestamp, prevHash, hash)
    expect(AuditRecord.safeParse(ev).success).toBe(false);
  });

  it('rejects a record with a missing engagementId', () => {
    const base = {
      actor: { kind: 'service' as const, id: 'worker-1' },
      type: 'run_finished' as const,
      payload: { runId: 'run-1', status: 'succeeded' as const },
      seq: 0,
      timestamp: 1000,
      prevHash: GENESIS_PREV_HASH,
      hash: SAMPLE_HASH,
    };
    expect(AuditRecord.safeParse(base).success).toBe(false);
    expect(AuditEvent.safeParse({ ...base, engagementId: '' }).success).toBe(false);
  });

  it('rejects a record with a missing actor', () => {
    const base = {
      engagementId: SAMPLE_ENGAGEMENT_ID,
      type: 'run_finished' as const,
      payload: { runId: 'run-1', status: 'succeeded' as const },
      seq: 0,
      timestamp: 1000,
      prevHash: GENESIS_PREV_HASH,
      hash: SAMPLE_HASH,
    };
    expect(AuditRecord.safeParse(base).success).toBe(false);
    expect(AuditEvent.safeParse(base).success).toBe(false);
  });
});
