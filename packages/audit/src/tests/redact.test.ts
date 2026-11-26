import { describe, expect, it } from 'vitest';
import {
  makeAuthFailureEvent,
  makeChain,
  makeDecisionEvent,
  makeRunFinishedEvent,
  makeRunStartedEvent,
  makeStatusChangedEvent,
  SAMPLE_ENGAGEMENT_ID,
} from '../__fixtures__/event';
import { verifyChain } from '../chain';
import { REDACTED_VALUE, redactRecord, redactRecords } from '../redact';
import { AuditRecord } from '../types';

describe('redactRecord', () => {
  const records = makeChain([
    makeStatusChangedEvent(),
    makeDecisionEvent(),
    makeRunStartedEvent(),
    makeRunFinishedEvent(),
    makeAuthFailureEvent(),
  ]);

  it('redacts actor.id and auth_failure.sourceIp by default without mutating input', () => {
    const authRecord = records[4]!;
    const originalCopy = structuredClone(authRecord);

    const redacted = redactRecord(authRecord);

    expect(authRecord).toEqual(originalCopy);
    expect(redacted.actor.id).toBe(REDACTED_VALUE);
    expect(redacted.actor.kind).toBe(authRecord.actor.kind);
    expect(redacted.type).toBe('auth_failure');

    // redacted: true is an extra key — strict AuditRecord schema rejects it.
    // Redacted output is for display only; auditors verify the unredacted chain.
    expect(AuditRecord.safeParse(redacted).success).toBe(false);

    // Redacted flag is present
    expect(redacted.redacted).toBe(true);

    // Preserves chain metadata
    expect(redacted.seq).toBe(authRecord.seq);
    expect(redacted.prevHash).toBe(authRecord.prevHash);
    expect(redacted.hash).toBe(authRecord.hash);

    // sourceIp is redacted
    expect(redacted.type).toBe('auth_failure');
    if (redacted.type === 'auth_failure') {
      expect(redacted.payload.sourceIp).toBe(REDACTED_VALUE);
      expect(redacted.payload.reason).toBe('forbidden');
    } else {
      throw new Error(`Unexpected type: ${String(redacted.type)}`);
    }
  });

  it('leaves targets and reasons unredacted by default', () => {
    const decision = redactRecord(records[1]!);
    // Guard against silently vacuous narrowing
    expect(decision.type).toBe('decision');
    if (decision.type === 'decision') {
      expect(decision.payload.target.host).toBe('example.com');
      expect(decision.payload.target.urlPath).toBe('/api/v1');
      expect(decision.payload.resolution?.ips).toEqual(['203.0.113.5']);
    } else {
      throw new Error(`Unexpected type: ${String(decision.type)}`);
    }

    const status = redactRecord(records[0]!);
    expect(status.type).toBe('engagement_status_changed');
    if (status.type === 'engagement_status_changed') {
      expect(status.payload.reason).toBe(
        'Signed authorization received from client',
      );
    } else {
      throw new Error(`Unexpected type: ${String(status.type)}`);
    }
  });

  it('redacts targets and resolutions when targets: true', () => {
    const decision = redactRecord(records[1]!, { targets: true });
    // Redacted record is NOT a valid AuditRecord (extra `redacted: true` field)
    expect(AuditRecord.safeParse(decision).success).toBe(false);
    expect(decision.type).toBe('decision');
    if (decision.type === 'decision') {
      expect(decision.payload.target.host).toBe(REDACTED_VALUE);
      expect(decision.payload.target.urlPath).toBe(REDACTED_VALUE);
      expect(decision.payload.target.port).toBe(443);
      expect(decision.payload.resolution).toEqual({
        ips: [REDACTED_VALUE],
        cnames: [REDACTED_VALUE],
      });
    } else {
      throw new Error(`Unexpected type: ${String(decision.type)}`);
    }

    const runStarted = redactRecord(records[2]!, { targets: true });
    expect(AuditRecord.safeParse(runStarted).success).toBe(false);
    expect(runStarted.type).toBe('run_started');
    if (runStarted.type === 'run_started') {
      expect(runStarted.payload.target.host).toBe(REDACTED_VALUE);
      expect(runStarted.payload.target.urlPath).toBe(REDACTED_VALUE);
    } else {
      throw new Error(`Unexpected type: ${String(runStarted.type)}`);
    }
  });

  it('redacts engagement status change reason when reasons: true', () => {
    const status = redactRecord(records[0]!, { reasons: true });
    expect(AuditRecord.safeParse(status).success).toBe(false);
    expect(status.type).toBe('engagement_status_changed');
    if (status.type === 'engagement_status_changed') {
      expect(status.payload.reason).toBe(REDACTED_VALUE);
    } else {
      throw new Error(`Unexpected type: ${String(status.type)}`);
    }
  });

  it('can disable default actor and sourceIp redaction', () => {
    const authRecord = records[4]!;
    const unredacted = redactRecord(authRecord, {
      actors: false,
      sourceIps: false,
    });
    // actor and sourceIp are preserved; only redacted: true differs
    expect(unredacted.actor).toEqual(authRecord.actor);
    expect(unredacted.type).toBe('auth_failure');
    if (unredacted.type === 'auth_failure') {
      expect(unredacted.payload.sourceIp).toBe('198.51.100.42');
    } else {
      throw new Error(`Unexpected type: ${String(unredacted.type)}`);
    }
    // The unredacted original still verifies
    expect(verifyChain([records[0]!, records[1]!, records[2]!, records[3]!, authRecord], {
      engagementId: SAMPLE_ENGAGEMENT_ID,
    }).ok).toBe(true);
  });

  it('is rejected by AuditRecord.parse even when no fields are redacted', () => {
    // redacted: true is always present and always fails strict() — this is intentional.
    const record = records[0]!;
    const redacted = redactRecord(record, { actors: false });
    expect(AuditRecord.safeParse(redacted).success).toBe(false);
  });

  it('causes verifyChain to detect INVALID_RECORD for a redacted record', () => {
    // verifyChain re-parses each record; a redacted record fails AuditRecord and is INVALID_RECORD.
    const redactedChain = redactRecords(records);
    const result = verifyChain(redactedChain, {
      engagementId: SAMPLE_ENGAGEMENT_ID,
    });
    expect(result).toMatchObject({
      ok: false,
      index: 0,
      code: 'INVALID_RECORD',
    });
  });

  it('causes verifyChain to detect HASH_MISMATCH for a redacted record passed as an AuditRecord', () => {
    // If someone casts around the type system and passes a redacted record after stripping
    // the extra key, it still fails at hash verification because the content differs.
    const redactedChain = redactRecords(records).map(({ redacted: _r, ...rest }) => rest);
    const result = verifyChain(redactedChain, {
      engagementId: SAMPLE_ENGAGEMENT_ID,
    });
    // Actor id was redacted so hash won't match
    expect(result).toMatchObject({
      ok: false,
      index: 0,
      seq: 0,
      code: 'HASH_MISMATCH',
    });
  });
});
