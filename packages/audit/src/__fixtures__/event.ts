import { buildRecord, GENESIS_PREV_HASH } from '../chain';
import type { Actor, AuditEvent, AuditRecord } from '../types';

export const SAMPLE_HASH = 'a'.repeat(64);
export const SAMPLE_ENGAGEMENT_ID = 'eng-1';

export const USER_ACTOR: Actor = Object.freeze({ kind: 'user', id: 'alice@example.com' });
export const SERVICE_ACTOR: Actor = Object.freeze({ kind: 'service', id: 'scanner-worker-1' });
export const SYSTEM_ACTOR: Actor = Object.freeze({ kind: 'system', id: 'scope-guard' });

export function makeDecisionEvent(
  overrides: Partial<Extract<AuditEvent, { type: 'decision' }>> = {},
): Extract<AuditEvent, { type: 'decision' }> {
  return {
    engagementId: SAMPLE_ENGAGEMENT_ID,
    actor: SERVICE_ACTOR,
    type: 'decision',
    payload: {
      target: {
        host: 'example.com',
        port: 443,
        protocol: 'https',
        urlPath: '/api/v1',
      },
      toolClass: 'active-light',
      allowed: true,
      reasons: ['INCLUDED'],
      matchedRuleIds: ['rule-1'],
      scopeVersionHash: SAMPLE_HASH,
      evaluatedAt: 1_700_000_000_000,
      resolution: {
        ips: ['203.0.113.5'],
        cnames: ['edge.example.com'],
      },
    },
    ...overrides,
  };
}

export function makeRunStartedEvent(
  runId = 'run-1',
  engagementId = SAMPLE_ENGAGEMENT_ID,
): Extract<AuditEvent, { type: 'run_started' }> {
  return {
    engagementId,
    actor: SERVICE_ACTOR,
    type: 'run_started',
    payload: {
      runId,
      tool: 'subfinder',
      target: { host: 'example.com', urlPath: '/admin' },
      toolClass: 'passive',
      scopeVersionHash: SAMPLE_HASH,
    },
  };
}

export function makeRunFinishedEvent(
  runId = 'run-1',
  status: 'succeeded' | 'failed' | 'cancelled' | 'timed_out' = 'succeeded',
  engagementId = SAMPLE_ENGAGEMENT_ID,
): Extract<AuditEvent, { type: 'run_finished' }> {
  return {
    engagementId,
    actor: SERVICE_ACTOR,
    type: 'run_finished',
    payload: { runId, status },
  };
}

export function makeAuthFailureEvent(
  engagementId = SAMPLE_ENGAGEMENT_ID,
): Extract<AuditEvent, { type: 'auth_failure' }> {
  return {
    engagementId,
    actor: SYSTEM_ACTOR,
    type: 'auth_failure',
    payload: {
      reason: 'forbidden',
      sourceIp: '198.51.100.42',
    },
  };
}

export function makeStatusChangedEvent(
  engagementId = SAMPLE_ENGAGEMENT_ID,
): Extract<AuditEvent, { type: 'engagement_status_changed' }> {
  return {
    engagementId,
    actor: USER_ACTOR,
    type: 'engagement_status_changed',
    payload: {
      from: 'draft',
      to: 'active',
      reason: 'Signed authorization received from client',
    },
  };
}

export function makeChain(
  events: readonly AuditEvent[],
  startTimestamp = 1000,
): AuditRecord[] {
  const out: AuditRecord[] = [];
  let prevHash = GENESIS_PREV_HASH;
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    const record = buildRecord(event, {
      seq: i,
      prevHash,
      timestamp: startTimestamp + i * 10,
    });
    out.push(record);
    prevHash = record.hash;
  }
  return out;
}

