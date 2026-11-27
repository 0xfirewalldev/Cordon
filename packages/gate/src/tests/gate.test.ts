import type { AuditLog } from '@scope-guard/audit';
import type { CompiledScope } from '@scope-guard/scope';
import { describe, expect, it } from 'vitest';
import { createAuditApprovals } from '../approvals';
import type { ScopeApprovals } from '../approvals';
import { createGate, INVALID_TARGET_HOST } from '../gate';
import type { GateDeps, GateResult, Resolver } from '../gate';
import {
  ALICE,
  BASE_RULES,
  ENG,
  NOW,
  WORKER,
  approvedEvent,
  approve,
  createdEvent,
  makeScope,
  mustAppend,
  newLog,
  widerScope,
} from './helpers';

const req = (
  target: string,
  toolClass = 'passive',
  extra: Record<string, unknown> = {}
) => ({
  engagementId: ENG,
  actor: WORKER,
  toolClass,
  target,
  ...extra,
});

function resolverOf(answer: unknown) {
  const calls: string[] = [];
  const resolver: Resolver = {
    async resolve(host) {
      calls.push(host);
      return answer;
    },
  };
  return { resolver, calls };
}

async function setup(
  deps: Partial<GateDeps> = {},
  scope: CompiledScope = makeScope()
) {
  const log = newLog();
  await approve(log, scope);
  const gate = createGate({
    audit: log,
    approvals: createAuditApprovals(log),
    now: () => NOW,
    ...deps,
  });
  return { log, gate, scope };
}

const allowedOf = (r: GateResult) => {
  if (!r.allowed)
    throw new Error(`expected allowed, got ${JSON.stringify(r.reasons)}`);
  return r;
};
const deniedOf = (r: GateResult) => {
  if (r.allowed) throw new Error('expected a denial');
  return r;
};
const decisionRecords = async (log: AuditLog) =>
  (await log.list(ENG)).filter(r => r.type === 'decision');

describe('allowed', () => {
  it('allows a passive in-scope domain, records the decision, and pins nothing', async () => {
    const { gate, scope, log } = await setup();
    const r = allowedOf(await gate.check(scope, req('example.com')));
    expect(r.decision).toMatchObject({
      allowed: true,
      reasons: ['INCLUDED'],
      matchedRuleIds: ['r1'],
    });
    expect(r.ips).toStrictEqual([]);
    expect(r.target.host).toStrictEqual({ kind: 'name', name: 'example.com' });

    const [rec] = await decisionRecords(log);
    expect(rec).toStrictEqual(r.record);
    expect(rec?.payload).toMatchObject({
      allowed: true,
      reasons: ['INCLUDED'],
      scopeVersionHash: scope.hash,
      evaluatedAt: NOW,
      toolClass: 'passive',
      target: { host: 'example.com' },
    });
    expect(rec?.actor).toStrictEqual(WORKER);
  });

  it('resolves an active target using the NORMALIZED name and pins the resolved IPs', async () => {
    const { resolver, calls } = resolverOf({
      ips: ['198.51.100.10'],
      cnames: [],
    });
    const { gate, scope, log } = await setup({ resolver });
    const r = allowedOf(
      await gate.check(scope, req('EXAMPLE.com.', 'active-light'))
    );
    expect(calls).toStrictEqual(['example.com']);
    expect(r.ips).toStrictEqual(['198.51.100.10']);

    const [rec] = await decisionRecords(log);
    expect(rec?.payload).toMatchObject({
      target: { host: 'example.com' },
      resolution: { ips: ['198.51.100.10'], cnames: [] },
    });
  });

  it('accepts the array form of resolution', async () => {
    const { resolver } = resolverOf(['198.51.100.10']);
    const { gate, scope } = await setup({ resolver });
    expect(
      allowedOf(await gate.check(scope, req('example.com', 'active-light'))).ips
    ).toStrictEqual(['198.51.100.10']);
  });

  it('allows an IP target without resolving, and pins that IP', async () => {
    const { resolver, calls } = resolverOf({ ips: ['203.0.113.9'] });
    const { gate, scope } = await setup({ resolver });
    const r = allowedOf(
      await gate.check(scope, req('198.51.100.7', 'active-light'))
    );
    expect(r.ips).toStrictEqual(['198.51.100.7']);
    expect(calls).toStrictEqual([]);
  });

  it('does not resolve for passive tools', async () => {
    const { resolver, calls } = resolverOf({ ips: ['203.0.113.9'] });
    const { gate, scope } = await setup({ resolver });
    allowedOf(await gate.check(scope, req('example.com', 'passive')));
    expect(calls).toStrictEqual([]);
  });

  it('allows an in-scope URL and records its path', async () => {
    const { gate, scope, log } = await setup();
    allowedOf(await gate.check(scope, req('https://Example.com/ok/../fine')));
    const [rec] = await decisionRecords(log);
    expect(rec?.payload).toMatchObject({
      target: {
        host: 'example.com',
        port: 443,
        protocol: 'https',
        urlPath: '/fine',
      },
    });
  });

  it('leaves a chain that verifies', async () => {
    const { resolver } = resolverOf({ ips: ['198.51.100.10'], cnames: [] });
    const { gate, scope, log } = await setup({ resolver });
    await gate.check(scope, req('example.com'));
    await gate.check(scope, req('198.51.100.66'));
    await gate.check(scope, req('example.com', 'active-light'));
    await gate.check(scope, req('bad host!'));
    expect((await log.verify(ENG)).ok).toBe(true);
  });
});

describe('denied by scope', () => {
  it.each([
    ['an excluded IP', '198.51.100.66', 'passive', ['EXCLUDED'], ['r4']],
    [
      'an excluded URL',
      'https://example.com/admin/users',
      'passive',
      ['EXCLUDED'],
      ['r5'],
    ],
    [
      'a target nothing includes',
      'other.org',
      'passive',
      ['NO_INCLUDE_MATCH'],
      [],
    ],
    [
      'an IPv6 spelling of an excluded address',
      '::ffff:198.51.100.66',
      'passive',
      ['EXCLUDED'],
      ['r4'],
    ],
  ])('%s', async (_label, target, toolClass, reasons, ruleIds) => {
    const { gate, scope, log } = await setup();
    const r = deniedOf(await gate.check(scope, req(target, toolClass)));
    expect(r.reasons).toStrictEqual(reasons);
    expect(r.decision?.matchedRuleIds).toStrictEqual(ruleIds);
    expect(r.audited).toBe(true);
    const [rec] = await decisionRecords(log);
    expect(rec?.payload).toMatchObject({ allowed: false, reasons });
  });

  it('denies outside the engagement window', async () => {
    const { gate, scope } = await setup({ now: () => Date.UTC(2027, 0, 1) });
    expect(
      deniedOf(await gate.check(scope, req('example.com'))).reasons
    ).toStrictEqual(['OUTSIDE_WINDOW']);
  });

  it('denies when the clock is invalid', async () => {
    const { gate, scope } = await setup({ now: () => Number.NaN });
    const r = deniedOf(await gate.check(scope, req('example.com')));
    expect(r.reasons).toStrictEqual(['OUTSIDE_WINDOW']);
    expect(r.audited).toBe(true);
  });
});

describe('resolution', () => {
  it('denies an active tool when there is no resolver', async () => {
    const { gate, scope } = await setup();
    expect(
      deniedOf(await gate.check(scope, req('example.com', 'active-light')))
        .reasons
    ).toStrictEqual(['RESOLUTION_REQUIRED']);
  });

  it('denies when the resolver throws', async () => {
    const resolver: Resolver = {
      resolve: async () => {
        throw new Error('SERVFAIL');
      },
    };
    const { gate, scope } = await setup({ resolver });
    expect(
      deniedOf(await gate.check(scope, req('example.com', 'active-light')))
        .reasons
    ).toStrictEqual(['RESOLUTION_REQUIRED']);
  });

  it('denies when the resolver times out, without waiting forever', async () => {
    const resolver: Resolver = { resolve: () => new Promise(() => {}) };
    const { gate, scope } = await setup({ resolver, resolveTimeoutMs: 30 });
    const started = Date.now();
    const r = deniedOf(
      await gate.check(scope, req('example.com', 'active-light'))
    );
    expect(r.reasons).toStrictEqual(['RESOLUTION_REQUIRED']);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('denies a resolved IP outside every include', async () => {
    const { resolver } = resolverOf({ ips: ['203.0.113.9'] });
    const { gate, scope } = await setup({ resolver });
    expect(
      deniedOf(await gate.check(scope, req('example.com', 'active-light')))
        .reasons
    ).toStrictEqual(['RESOLVED_IP_OUT_OF_SCOPE']);
  });

  it('denies a resolved IP that is excluded, including its IPv6 spelling', async () => {
    const { resolver } = resolverOf({ ips: ['::ffff:198.51.100.66'] });
    const { gate, scope } = await setup({ resolver });
    const r = deniedOf(
      await gate.check(scope, req('example.com', 'active-light'))
    );
    expect(r.reasons).toStrictEqual(['RESOLVED_IP_OUT_OF_SCOPE']);
    expect(r.decision?.matchedRuleIds).toStrictEqual(['r4']);
  });

  it('denies a CNAME that points outside scope', async () => {
    const { resolver } = resolverOf({
      ips: ['198.51.100.10'],
      cnames: ['victim.thirdparty.net'],
    });
    const { gate, scope } = await setup({ resolver });
    expect(
      deniedOf(await gate.check(scope, req('example.com', 'active-light')))
        .reasons
    ).toStrictEqual(['CNAME_OUT_OF_SCOPE']);
  });

  it.each([
    ['a string', 'not an answer'],
    ['null', null],
    ['an invalid IP', { ips: ['198.51.100.10', 'not-an-ip'] }],
    ['IP shorthand', { ips: ['127.1'] }],
    ['an unknown key', { ips: ['198.51.100.10'], extra: 1 }],
    [
      'too many IPs',
      { ips: Array.from({ length: 65 }, () => '198.51.100.10') },
    ],
  ])(
    'denies a malformed resolution (%s) and audits it',
    async (_label, answer) => {
      const { resolver } = resolverOf(answer);
      const { gate, scope, log } = await setup({ resolver });
      const r = deniedOf(
        await gate.check(scope, req('example.com', 'active-light'))
      );
      expect(r.reasons).toStrictEqual(['INVALID_RESOLUTION']);
      expect(r.audited).toBe(true);
      expect((await decisionRecords(log)).length).toBe(1);
    }
  );
});

describe('denied before evaluation', () => {
  it('denies an unparseable target without logging the raw input', async () => {
    const { gate, scope, log } = await setup();
    const r = deniedOf(
      await gate.check(scope, req('<script>alert(1)</script> not a host'))
    );
    expect(r.reasons).toStrictEqual(['INVALID_TARGET']);
    expect(r.audited).toBe(true);
    const [rec] = await decisionRecords(log);
    expect(rec?.payload).toMatchObject({
      target: { host: INVALID_TARGET_HOST },
      allowed: false,
    });
    expect(JSON.stringify(rec)).not.toContain('script');
  });

  it('denies a scope that belongs to another engagement', async () => {
    const { gate, log } = await setup();
    const foreign = makeScope(BASE_RULES, 'eng-2');
    expect(
      deniedOf(await gate.check(foreign, req('example.com'))).reasons
    ).toStrictEqual(['SCOPE_ENGAGEMENT_MISMATCH']);
    expect((await decisionRecords(log)).length).toBe(1);
  });

  it('lists every problem, not just the first', async () => {
    const { gate } = await setup();
    const foreign = makeScope(BASE_RULES, 'eng-2');
    expect(
      deniedOf(await gate.check(foreign, req('bad host!'))).reasons
    ).toStrictEqual(['INVALID_TARGET', 'SCOPE_ENGAGEMENT_MISMATCH']);
  });

  it('denies a scope that was never approved', async () => {
    const log = newLog();
    const gate = createGate({
      audit: log,
      approvals: createAuditApprovals(log),
      now: () => NOW,
    });
    expect(
      deniedOf(await gate.check(makeScope(), req('example.com'))).reasons
    ).toStrictEqual(['SCOPE_NOT_APPROVED']);
  });

  it('denies a self-approved scope', async () => {
    const log = newLog();
    const scope = makeScope();
    await mustAppend(log, createdEvent(scope, ALICE));
    await mustAppend(log, approvedEvent(scope, ALICE));
    const gate = createGate({
      audit: log,
      approvals: createAuditApprovals(log),
      now: () => NOW,
    });
    expect(
      deniedOf(await gate.check(scope, req('example.com'))).reasons
    ).toStrictEqual(['SCOPE_NOT_APPROVED']);
  });

  it('denies a superseded scope and allows the current one', async () => {
    const log = newLog();
    const v1 = makeScope();
    const v2 = widerScope();
    await approve(log, v1);
    await approve(log, v2);
    const gate = createGate({
      audit: log,
      approvals: createAuditApprovals(log),
      now: () => NOW,
    });
    expect(
      deniedOf(await gate.check(v1, req('example.com'))).reasons
    ).toStrictEqual(['SCOPE_NOT_CURRENT']);
    allowedOf(await gate.check(v2, req('example.com')));
  });

  it('denies when the approval check fails', async () => {
    const approvals: ScopeApprovals = {
      latestApprovedHash: async () => {
        throw new Error('db down');
      },
    };
    const log = newLog();
    const gate = createGate({ audit: log, approvals, now: () => NOW });
    const r = deniedOf(await gate.check(makeScope(), req('example.com')));
    expect(r.reasons).toStrictEqual(['APPROVAL_CHECK_FAILED']);
    expect(r.audited).toBe(true);
  });

  it('does not evaluate or resolve when a pre-check fails', async () => {
    const { resolver, calls } = resolverOf({ ips: ['198.51.100.10'] });
    const log = newLog();
    const gate = createGate({
      audit: log,
      approvals: createAuditApprovals(log),
      resolver,
      now: () => NOW,
    });
    deniedOf(await gate.check(makeScope(), req('example.com', 'active-light')));
    expect(calls).toStrictEqual([]);
  });
});

describe('invalid requests', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'example.com'],
    ['an empty object', {}],
    ['an unknown key', req('example.com', 'passive', { extra: true })],
    [
      'a missing target',
      { engagementId: ENG, actor: WORKER, toolClass: 'passive' },
    ],
    ['an empty target', req('')],
    ['an oversized target', req('a'.repeat(3000))],
    ['an unknown tool class', req('example.com', 'aggressive')],
    ['a string actor', req('example.com', 'passive', { actor: 'alice' })],
    [
      'an empty engagementId',
      req('example.com', 'passive', { engagementId: '' }),
    ],
    ['a non-string target', req('example.com', 'passive', { target: 42 })],
  ])('denies %s and writes nothing', async (_label, request) => {
    const { gate, scope, log } = await setup();
    const before = (await log.list(ENG)).length;
    const r = deniedOf(await gate.check(scope, request));
    expect(r.reasons).toStrictEqual(['INVALID_REQUEST']);
    expect(r.audited).toBe(false);
    expect((await log.list(ENG)).length).toBe(before);
  });
});

describe('fail closed', () => {
  const failingAudit = {
    append: async () => ({
      ok: false as const,
      code: 'STORE_ERROR' as const,
      message: 'down',
    }),
  };

  it('denies an in-scope action when the decision cannot be written', async () => {
    const scope = makeScope();
    const approvals: ScopeApprovals = {
      latestApprovedHash: async () => scope.hash,
    };
    const gate = createGate({ audit: failingAudit, approvals, now: () => NOW });
    const r = deniedOf(await gate.check(scope, req('example.com')));
    expect(r.reasons).toStrictEqual(['AUDIT_UNAVAILABLE']);
    expect(r.audited).toBe(false);
    expect(r.decision).toBeUndefined();
  });

  it('keeps the real reasons when a denial cannot be written', async () => {
    const scope = makeScope();
    const approvals: ScopeApprovals = {
      latestApprovedHash: async () => scope.hash,
    };
    const gate = createGate({ audit: failingAudit, approvals, now: () => NOW });
    const r = deniedOf(await gate.check(scope, req('198.51.100.66')));
    expect(r.reasons).toStrictEqual(['EXCLUDED']);
    expect(r.audited).toBe(false);
    expect(r.decision?.allowed).toBe(false);
  });

  it('denies a pre-check failure that cannot be written, with its reasons', async () => {
    const approvals: ScopeApprovals = { latestApprovedHash: async () => null };
    const gate = createGate({ audit: failingAudit, approvals, now: () => NOW });
    const r = deniedOf(await gate.check(makeScope(), req('example.com')));
    expect(r.reasons).toStrictEqual(['SCOPE_NOT_APPROVED']);
    expect(r.audited).toBe(false);
  });

  it('never throws: an exception anywhere is GATE_ERROR', async () => {
    const scope = makeScope();
    const approvals: ScopeApprovals = {
      latestApprovedHash: async () => scope.hash,
    };
    const throwingAudit = {
      append: async () => {
        throw new Error('boom');
      },
    };
    const a = createGate({ audit: throwingAudit, approvals, now: () => NOW });
    expect(
      deniedOf(await a.check(scope, req('example.com'))).reasons
    ).toStrictEqual(['GATE_ERROR']);

    const b = createGate({
      audit: failingAudit,
      approvals,
      now: () => {
        throw new Error('clock');
      },
    });
    expect(
      deniedOf(await b.check(scope, req('example.com'))).reasons
    ).toStrictEqual(['GATE_ERROR']);
  });

  it('never allows without an audit record', async () => {
    const { gate, scope, log } = await setup();
    for (const target of [
      'example.com',
      'a.example.com',
      '198.51.100.7',
      'https://example.com/ok',
    ]) {
      const r = await gate.check(scope, req(target));
      if (r.allowed) {
        const stored = (await log.list(ENG)).find(
          x => x.hash === r.record.hash
        );
        expect(stored).toStrictEqual(r.record);
      }
    }
  });
});

describe('construction', () => {
  it.each([0, -1, 1.5, Number.NaN])('rejects resolveTimeoutMs %s', ms => {
    const log = newLog();
    expect(() =>
      createGate({
        audit: log,
        approvals: createAuditApprovals(log),
        resolveTimeoutMs: ms,
      })
    ).toThrow(RangeError);
  });
});
