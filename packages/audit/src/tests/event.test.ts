import type { ZodType } from 'zod';
import { describe, expect, it } from 'vitest';
import {
  AuthFailurePayload,
  DecisionPayload,
  EngagementStatusChangedPayload,
  RunFinishedPayload,
  RunStartedPayload,
  ScopeVersionApprovedPayload,
  ScopeVersionCreatedPayload,
} from '../events';

const HASH = 'a'.repeat(64);
const parses = (schema: ZodType, value: unknown) => schema.safeParse(value).success;

describe('DecisionPayload', () => {
  const valid = {
    target: { host: 'example.com', port: 443, protocol: 'https', urlPath: '/admin' },
    toolClass: 'active-light',
    allowed: false,
    reasons: ['EXCLUDED'],
    matchedRuleIds: ['r-url-admin'],
    scopeVersionHash: HASH,
    evaluatedAt: Date.UTC(2026, 5, 1),
    resolution: { ips: ['198.51.100.10'], cnames: ['cdn.example.com'] },
  };

  it('parses a full payload, a minimal one, and an IPv6 host', () => {
    expect(parses(DecisionPayload, valid)).toBe(true);
    const { resolution: _r, ...rest } = valid;
    expect(parses(DecisionPayload, { ...rest, target: { host: '203.0.113.5' } })).toBe(true);
    expect(parses(DecisionPayload, { ...valid, target: { host: '2001:db8::1' } })).toBe(true);
  });

  it.each([
    ['an unknown key', { ...valid, extra: true }],
    ['an unknown key in target', { ...valid, target: { host: 'example.com', extra: 1 } }],
    ['an unknown key in resolution', { ...valid, resolution: { ips: [], cnames: [], extra: 1 } }],
    ['a missing target', { ...valid, target: undefined }],
    ['an empty host', { ...valid, target: { host: '' } }],
    ['port 0', { ...valid, target: { host: 'example.com', port: 0 } }],
    ['port 65536', { ...valid, target: { host: 'example.com', port: 65536 } }],
    ['an unknown tool class', { ...valid, toolClass: 'aggressive' }],
    ['empty reasons', { ...valid, reasons: [] }],
    ['17 reasons', { ...valid, reasons: Array.from({ length: 17 }, () => 'X') }],
    ['a bad scope hash', { ...valid, scopeVersionHash: 'xyz' }],
    ['an uppercase scope hash', { ...valid, scopeVersionHash: 'A'.repeat(64) }],
    ['a fractional timestamp', { ...valid, evaluatedAt: 1.5 }],
    ['a negative timestamp', { ...valid, evaluatedAt: -1 }],
    ['a bigint timestamp', { ...valid, evaluatedAt: 1n }],
    ['a Date timestamp', { ...valid, evaluatedAt: new Date() }],
    ['a non-boolean allowed', { ...valid, allowed: 'yes' }],
    ['65 resolved IPs', { ...valid, resolution: { ips: Array.from({ length: 65 }, () => '198.51.100.10'), cnames: [] } }],
    ['17 CNAMEs', { ...valid, resolution: { ips: [], cnames: Array.from({ length: 17 }, () => 'cdn.example.com') } }],
    ['1001 matched rule ids', { ...valid, matchedRuleIds: Array.from({ length: 1001 }, (_, i) => `r${i}`) }],
    ['an oversized url path', { ...valid, target: { host: 'example.com', urlPath: `/${'a'.repeat(2100)}` } }],
  ])('rejects %s', (_label, value) => {
    expect(parses(DecisionPayload, value)).toBe(false);
  });

  it.each([null, undefined, 42, 'x', []])('rejects non-object %j', (value) => {
    expect(parses(DecisionPayload, value)).toBe(false);
  });
});

describe('ScopeVersionCreatedPayload', () => {
  const valid = {
    scopeVersionId: 'sv-1',
    versionHash: HASH,
    ruleCount: 8,
    notBefore: 1000,
    notAfter: 2000,
  };

  it('parses valid payloads, including an empty scope', () => {
    expect(parses(ScopeVersionCreatedPayload, valid)).toBe(true);
    expect(parses(ScopeVersionCreatedPayload, { ...valid, ruleCount: 0 })).toBe(true);
    expect(parses(ScopeVersionCreatedPayload, { ...valid, ruleCount: 10_000 })).toBe(true);
  });

  it.each([
    ['a duplicate timestamp key', { ...valid, createdAt: 1 }],
    ['a missing id', { ...valid, scopeVersionId: undefined }],
    ['an empty id', { ...valid, scopeVersionId: '' }],
    ['a bad hash', { ...valid, versionHash: 'nope' }],
    ['a negative rule count', { ...valid, ruleCount: -1 }],
    ['a fractional rule count', { ...valid, ruleCount: 1.5 }],
    ['10001 rules', { ...valid, ruleCount: 10_001 }],
    ['notBefore equal to notAfter', { ...valid, notBefore: 2000, notAfter: 2000 }],
    ['notBefore after notAfter', { ...valid, notBefore: 3000, notAfter: 2000 }],
    ['a fractional window', { ...valid, notBefore: 1000.5 }],
  ])('rejects %s', (_label, value) => {
    expect(parses(ScopeVersionCreatedPayload, value)).toBe(false);
  });
});

describe('ScopeVersionApprovedPayload', () => {
  const valid = { scopeVersionId: 'sv-1', versionHash: HASH };

  it('parses a valid payload', () => {
    expect(parses(ScopeVersionApprovedPayload, valid)).toBe(true);
  });

  it.each([
    ['an approver field (the actor is on the record)', { ...valid, approvedBy: 'alice' }],
    ['an approval time field', { ...valid, approvedAt: 1 }],
    ['an empty id', { ...valid, scopeVersionId: '' }],
    ['a bad hash', { ...valid, versionHash: 'nope' }],
    ['a missing hash', { scopeVersionId: 'sv-1' }],
  ])('rejects %s', (_label, value) => {
    expect(parses(ScopeVersionApprovedPayload, value)).toBe(false);
  });
});

describe('EngagementStatusChangedPayload', () => {
  it('parses valid transitions, with and without a reason', () => {
    expect(parses(EngagementStatusChangedPayload, { from: 'draft', to: 'active' })).toBe(true);
    expect(
      parses(EngagementStatusChangedPayload, { from: 'active', to: 'paused', reason: 'client request' }),
    ).toBe(true);
  });

  it.each([
    ['from equal to to', { from: 'active', to: 'active' }],
    ['an unknown status', { from: 'draft', to: 'dormant' }],
    ['a tool-class value as status', { from: 'draft', to: 'active-light' }],
    ['a copied decision field', { from: 'draft', to: 'active', toolClass: 'passive' }],
    ['a time field', { from: 'draft', to: 'active', changedAt: 1 }],
    ['an empty reason', { from: 'draft', to: 'active', reason: '' }],
    ['a 501 character reason', { from: 'draft', to: 'active', reason: 'x'.repeat(501) }],
    ['a missing to', { from: 'draft' }],
  ])('rejects %s', (_label, value) => {
    expect(parses(EngagementStatusChangedPayload, value)).toBe(false);
  });
});

describe('RunStartedPayload', () => {
  const valid = {
    runId: 'run-1',
    tool: 'subfinder',
    target: { host: 'example.com' },
    toolClass: 'passive',
    scopeVersionHash: HASH,
  };

  it('parses a valid payload', () => {
    expect(parses(RunStartedPayload, valid)).toBe(true);
  });

  it.each([
    ['a start time field', { ...valid, startedAt: 1 }],
    ['a missing tool', { ...valid, tool: undefined }],
    ['a missing runId', { ...valid, runId: undefined }],
    ['an unknown tool class', { ...valid, toolClass: 'loud' }],
    ['a bad scope hash', { ...valid, scopeVersionHash: 'x' }],
    ['an invalid target', { ...valid, target: { host: '' } }],
  ])('rejects %s', (_label, value) => {
    expect(parses(RunStartedPayload, value)).toBe(false);
  });
});

describe('RunFinishedPayload', () => {
  it('parses every status, with and without an exit code', () => {
    for (const status of ['succeeded', 'failed', 'cancelled', 'timed_out']) {
      expect(parses(RunFinishedPayload, { runId: 'run-1', status })).toBe(true);
    }
    expect(parses(RunFinishedPayload, { runId: 'run-1', status: 'failed', exitCode: 2 })).toBe(true);
    expect(parses(RunFinishedPayload, { runId: 'run-1', status: 'failed', exitCode: -9 })).toBe(true);
  });

  it.each([
    ['an unknown status', { runId: 'run-1', status: 'done' }],
    ['a completion time field', { runId: 'run-1', status: 'succeeded', completedAt: 1 }],
    ['a duration field', { runId: 'run-1', status: 'succeeded', durationMs: 5 }],
    ['an exit code of 256', { runId: 'run-1', status: 'failed', exitCode: 256 }],
    ['a fractional exit code', { runId: 'run-1', status: 'failed', exitCode: 1.5 }],
    ['a missing runId', { status: 'succeeded' }],
  ])('rejects %s', (_label, value) => {
    expect(parses(RunFinishedPayload, value)).toBe(false);
  });
});

describe('AuthFailurePayload', () => {
  it('parses each reason code, with and without a source IP', () => {
    for (const reason of ['invalid_token', 'expired_session', 'forbidden']) {
      expect(parses(AuthFailurePayload, { reason })).toBe(true);
    }
    expect(parses(AuthFailurePayload, { reason: 'forbidden', sourceIp: '203.0.113.5' })).toBe(true);
  });

  it.each([
    ['free text instead of a code', { reason: 'wrong password for alice' }],
    ['a time field', { reason: 'forbidden', failedAt: 1 }],
    ['a token field', { reason: 'invalid_token', token: 'abc' }],
    ['an empty source IP', { reason: 'forbidden', sourceIp: '' }],
    ['an oversized source IP', { reason: 'forbidden', sourceIp: 'x'.repeat(46) }],
    ['a missing reason', {}],
  ])('rejects %s', (_label, value) => {
    expect(parses(AuthFailurePayload, value)).toBe(false);
  });
});