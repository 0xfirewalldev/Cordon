import { describe, expect, it } from 'vitest';
import { sampleScopeVersion } from '../__fixtures__/rules';
import { compileScope } from '../compile';
import type { CompiledScope } from '../compile';
import { evaluate } from '../evaluate';
import { parseIp } from '../ip';
import type { EvalContext, IpHost, Resolution, Target } from '../target';
import { Decision } from '../types';
import type { RawRule } from '../types';

const NOW = Date.UTC(2026, 5, 1);
const passive: EvalContext = { now: NOW, toolClass: 'passive' };
const active: EvalContext = { now: NOW, toolClass: 'active-light' };

const build = (rules: Omit<RawRule, 'id'>[]): CompiledScope => {
  const result = compileScope({
    ...sampleScopeVersion,
    rules: rules.map((r, i) => ({ id: `r${i + 1}`, ...r })),
  });
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.scope;
};

const ipHost = (s: string): IpHost => {
  const ip = parseIp(s);
  if (ip === null) throw new Error(`bad ip ${s}`);
  return { kind: 'ip', version: ip.version, value: ip.value };
};

type Extra = Omit<Target, 'host' | 'url'>;
const name = (n: string, extra: Extra = {}): Target => ({
  host: { kind: 'name', name: n },
  ...extra,
});
const ip = (s: string, extra: Extra = {}): Target => ({
  host: ipHost(s),
  ...extra,
});
const url = (
  n: string,
  path: string,
  scheme: 'http' | 'https' = 'https'
): Target => ({
  host: { kind: 'name', name: n },
  url: { scheme, path },
});
const resolved = (ips: string[] = [], cnames: string[] = []): Resolution => ({
  ips: ips.map(ipHost),
  cnames,
});

/** Runs evaluate and asserts the result is always a schema-valid Decision. */
const run = (
  scope: CompiledScope,
  target: Target,
  ctx: EvalContext = passive,
  resolution?: Resolution
): Decision => {
  const d = evaluate(scope, target, ctx, resolution);
  expect(Decision.safeParse(d).success).toBe(true);
  return d;
};

describe('window', () => {
  const scope = build([
    { targetType: 'domain', effect: 'include', pattern: 'example.com' },
  ]);
  const at = (now: number): EvalContext => ({ now, toolClass: 'passive' });

  it('denies before notBefore', () => {
    expect(
      run(scope, name('example.com'), at(scope.notBefore - 1))
    ).toMatchObject({
      allowed: false,
      reasons: ['OUTSIDE_WINDOW'],
      matchedRuleIds: [],
    });
  });

  it('allows from notBefore (inclusive)', () => {
    expect(run(scope, name('example.com'), at(scope.notBefore)).allowed).toBe(
      true
    );
  });

  it('allows up to notAfter - 1 and denies at notAfter (exclusive)', () => {
    expect(
      run(scope, name('example.com'), at(scope.notAfter - 1)).allowed
    ).toBe(true);
    expect(run(scope, name('example.com'), at(scope.notAfter))).toMatchObject({
      allowed: false,
      reasons: ['OUTSIDE_WINDOW'],
    });
  });

  it.each([1.5, Number.NaN, Number.POSITIVE_INFINITY, -1])(
    'treats an invalid now (%s) as outside the window',
    now => {
      expect(run(scope, name('example.com'), at(now))).toMatchObject({
        allowed: false,
        reasons: ['OUTSIDE_WINDOW'],
        evaluatedAt: 0,
      });
    }
  );

  it('reports the evaluation time and the scope hash', () => {
    const d = run(scope, name('example.com'));
    expect(d.evaluatedAt).toBe(NOW);
    expect(d.scopeVersionHash).toBe(scope.hash);
  });
});

describe('includes and excludes', () => {
  it('allows a covered target and reports the include rule', () => {
    const scope = build([
      { targetType: 'domain', effect: 'include', pattern: 'example.com' },
    ]);
    expect(run(scope, name('example.com'))).toStrictEqual({
      allowed: true,
      reasons: ['INCLUDED'],
      matchedRuleIds: ['r1'],
      scopeVersionHash: scope.hash,
      evaluatedAt: NOW,
    });
  });

  it('denies with NO_INCLUDE_MATCH when nothing covers the target', () => {
    const scope = build([
      { targetType: 'domain', effect: 'include', pattern: 'example.com' },
    ]);
    expect(run(scope, name('other.com'))).toMatchObject({
      allowed: false,
      reasons: ['NO_INCLUDE_MATCH'],
      matchedRuleIds: [],
    });
  });

  it('denies everything when the scope has no rules (default deny)', () => {
    expect(run(build([]), name('example.com'))).toMatchObject({
      allowed: false,
      reasons: ['NO_INCLUDE_MATCH'],
    });
  });

  it.each([
    [
      'exclude listed after the include',
      [
        { targetType: 'wildcard', effect: 'include', pattern: '*.example.com' },
        {
          targetType: 'domain',
          effect: 'exclude',
          pattern: 'admin.example.com',
        },
      ],
      'r2',
    ],
    [
      'exclude listed before the include',
      [
        {
          targetType: 'domain',
          effect: 'exclude',
          pattern: 'admin.example.com',
        },
        { targetType: 'wildcard', effect: 'include', pattern: '*.example.com' },
      ],
      'r1',
    ],
  ] as const)(
    'an exclude beats an include (%s)',
    (_label, rules, excludeId) => {
      const scope = build([...rules]);
      expect(run(scope, name('admin.example.com'))).toMatchObject({
        allowed: false,
        reasons: ['EXCLUDED'],
        matchedRuleIds: [excludeId],
      });
      expect(run(scope, name('a.example.com')).allowed).toBe(true);
    }
  );

  it('excludes a single IP out of an included CIDR', () => {
    const scope = build([
      { targetType: 'cidr', effect: 'include', pattern: '198.51.100.0/24' },
      { targetType: 'ip', effect: 'exclude', pattern: '198.51.100.7' },
    ]);
    expect(run(scope, ip('198.51.100.7'))).toMatchObject({
      allowed: false,
      reasons: ['EXCLUDED'],
      matchedRuleIds: ['r2'],
    });
    expect(run(scope, ip('198.51.100.8'))).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r1'],
    });
  });

  it('an IPv6 spelling of an excluded IPv4 address is still excluded', () => {
    const scope = build([
      { targetType: 'cidr', effect: 'include', pattern: '10.0.0.0/8' },
      { targetType: 'ip', effect: 'exclude', pattern: '10.0.0.1' },
    ]);
    expect(run(scope, ip('::ffff:10.0.0.1'))).toMatchObject({
      allowed: false,
      reasons: ['EXCLUDED'],
    });
  });
});

describe('constraints', () => {
  it('reports PORT_NOT_ALLOWED and the covering rule', () => {
    const scope = build([
      {
        targetType: 'domain',
        effect: 'include',
        pattern: 'example.com',
        ports: [443],
      },
    ]);
    expect(run(scope, name('example.com', { port: 80 }))).toMatchObject({
      allowed: false,
      reasons: ['PORT_NOT_ALLOWED'],
      matchedRuleIds: ['r1'],
    });
    expect(run(scope, name('example.com', { port: 443 })).allowed).toBe(true);
    expect(run(scope, name('example.com')).reasons).toStrictEqual([
      'PORT_NOT_ALLOWED',
    ]);
  });

  it('reports PROTOCOL_NOT_ALLOWED', () => {
    const scope = build([
      {
        targetType: 'domain',
        effect: 'include',
        pattern: 'example.com',
        protocols: ['https'],
      },
    ]);
    expect(run(scope, name('example.com', { protocol: 'ssh' }))).toMatchObject({
      allowed: false,
      reasons: ['PROTOCOL_NOT_ALLOWED'],
      matchedRuleIds: ['r1'],
    });
  });

  it('reports TOOL_CLASS_NOT_ALLOWED', () => {
    const scope = build([
      {
        targetType: 'domain',
        effect: 'include',
        pattern: 'example.com',
        toolClasses: ['active-light'],
      },
    ]);
    expect(run(scope, name('example.com'), passive)).toMatchObject({
      allowed: false,
      reasons: ['TOOL_CLASS_NOT_ALLOWED'],
      matchedRuleIds: ['r1'],
    });
  });

  it('another include that allows the target wins over a constrained one', () => {
    const scope = build([
      {
        targetType: 'domain',
        effect: 'include',
        pattern: 'example.com',
        ports: [443],
      },
      { targetType: 'domain', effect: 'include', pattern: 'example.com' },
    ]);
    expect(run(scope, name('example.com', { port: 80 }))).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r2'],
    });
  });

  it('an exclude constrained to a port applies on that port and when the port is unknown', () => {
    const scope = build([
      { targetType: 'cidr', effect: 'include', pattern: '203.0.113.0/24' },
      {
        targetType: 'ip',
        effect: 'exclude',
        pattern: '203.0.113.5',
        ports: [22],
      },
    ]);
    expect(run(scope, ip('203.0.113.5', { port: 22 })).reasons).toStrictEqual([
      'EXCLUDED',
    ]);
    expect(run(scope, ip('203.0.113.5')).reasons).toStrictEqual(['EXCLUDED']);
    expect(run(scope, ip('203.0.113.5', { port: 443 }))).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r1'],
    });
  });
});

describe('url targets', () => {
  it('applies url_prefix excludes on segment boundaries, across scheme and case', () => {
    const scope = build([
      { targetType: 'domain', effect: 'include', pattern: 'example.com' },
      {
        targetType: 'url_prefix',
        effect: 'exclude',
        pattern: 'https://example.com/admin',
      },
    ]);
    expect(run(scope, url('example.com', '/admin'))).toMatchObject({
      allowed: false,
      reasons: ['EXCLUDED'],
      matchedRuleIds: ['r2'],
    });
    expect(run(scope, url('example.com', '/admin/x')).reasons).toStrictEqual([
      'EXCLUDED',
    ]);
    expect(
      run(scope, url('example.com', '/ADMIN', 'http')).reasons
    ).toStrictEqual(['EXCLUDED']);
    expect(run(scope, url('example.com', '/administrator'))).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r1'],
    });
    // Host-only targets are not path-checked here; the gate re-checks every URL a tool requests.
    expect(run(scope, name('example.com')).allowed).toBe(true);
  });

  it('url_prefix includes allow matching URLs but never a host-only target', () => {
    const scope = build([
      {
        targetType: 'url_prefix',
        effect: 'include',
        pattern: 'https://example.com/app',
      },
    ]);
    expect(run(scope, url('example.com', '/app/x'))).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r1'],
    });
    expect(run(scope, url('example.com', '/other')).reasons).toStrictEqual([
      'NO_INCLUDE_MATCH',
    ]);
    expect(run(scope, name('example.com')).reasons).toStrictEqual([
      'NO_INCLUDE_MATCH',
    ]);
  });
});

describe('resolution', () => {
  const scope = build([
    { targetType: 'domain', effect: 'include', pattern: 'example.com' }, // r1
    { targetType: 'wildcard', effect: 'include', pattern: '*.example.com' }, // r2
    { targetType: 'cidr', effect: 'include', pattern: '198.51.100.0/24' }, // r3
    { targetType: 'ip', effect: 'exclude', pattern: '198.51.100.66' }, // r4
  ]);
  const example = name('example.com');

  it('active tools require resolution data', () => {
    expect(run(scope, example, active)).toMatchObject({
      allowed: false,
      reasons: ['RESOLUTION_REQUIRED'],
      matchedRuleIds: [],
    });
    expect(run(scope, example, active, resolved()).reasons).toStrictEqual([
      'RESOLUTION_REQUIRED',
    ]);
  });

  it('passive tools do not need resolution', () => {
    expect(run(scope, example, passive)).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r1'],
    });
  });

  it('allows when every hop is in scope, listing the rules in hop order', () => {
    expect(
      run(
        scope,
        example,
        active,
        resolved(['198.51.100.10'], ['cdn.example.com'])
      )
    ).toMatchObject({
      allowed: true,
      reasons: ['INCLUDED'],
      matchedRuleIds: ['r1', 'r2', 'r3'],
    });
  });

  it('denies an IP outside every include', () => {
    expect(
      run(scope, example, active, resolved(['203.0.113.9']))
    ).toMatchObject({
      allowed: false,
      reasons: ['RESOLVED_IP_OUT_OF_SCOPE'],
      matchedRuleIds: [],
    });
  });

  it('denies an excluded IP and names the excluding rule', () => {
    expect(
      run(scope, example, active, resolved(['198.51.100.66']))
    ).toMatchObject({
      allowed: false,
      reasons: ['RESOLVED_IP_OUT_OF_SCOPE'],
      matchedRuleIds: ['r4'],
    });
  });

  it('one bad IP among good ones denies the whole decision', () => {
    expect(
      run(scope, example, active, resolved(['198.51.100.10', '203.0.113.9']))
        .reasons
    ).toStrictEqual(['RESOLVED_IP_OUT_OF_SCOPE']);
  });

  it('denies a CNAME pointing outside scope', () => {
    expect(
      run(
        scope,
        example,
        active,
        resolved(['198.51.100.10'], ['victim.thirdparty.net'])
      )
    ).toMatchObject({
      allowed: false,
      reasons: ['CNAME_OUT_OF_SCOPE'],
    });
  });

  it('lists every failing reason in a fixed order: target, CNAMEs, IPs', () => {
    expect(
      run(
        scope,
        example,
        active,
        resolved(['203.0.113.9'], ['victim.thirdparty.net'])
      ).reasons
    ).toStrictEqual(['CNAME_OUT_OF_SCOPE', 'RESOLVED_IP_OUT_OF_SCOPE']);
    expect(
      run(scope, name('evil.com'), active, resolved(['203.0.113.9'])).reasons
    ).toStrictEqual(['NO_INCLUDE_MATCH', 'RESOLVED_IP_OUT_OF_SCOPE']);
  });

  it('an IPv4-mapped IPv6 hop is checked as IPv4', () => {
    const r: Resolution = { ips: [ipHost('::ffff:198.51.100.66')], cnames: [] };
    expect(run(scope, example, active, r)).toMatchObject({
      allowed: false,
      reasons: ['RESOLVED_IP_OUT_OF_SCOPE'],
      matchedRuleIds: ['r4'],
    });
  });

  it('still checks resolution a passive caller supplies', () => {
    expect(
      run(scope, example, passive, resolved(['203.0.113.9'])).reasons
    ).toStrictEqual(['RESOLVED_IP_OUT_OF_SCOPE']);
  });

  it('rejects oversized resolution instead of truncating it', () => {
    const manyIps = Array.from({ length: 65 }, () => '198.51.100.10');
    const manyCnames = Array.from({ length: 17 }, () => 'cdn.example.com');
    expect(
      run(scope, example, active, resolved(manyIps)).reasons
    ).toStrictEqual(['INVALID_TARGET']);
    expect(
      run(scope, example, active, resolved(['198.51.100.10'], manyCnames))
        .reasons
    ).toStrictEqual(['INVALID_TARGET']);
  });

  it('ignores resolution for IP targets', () => {
    expect(
      run(scope, ip('198.51.100.10'), active, resolved(['203.0.113.9']))
    ).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r3'],
    });
  });

  it('hops inherit the effective port from a URL target', () => {
    const portScoped = build([
      { targetType: 'domain', effect: 'include', pattern: 'example.com' },
      {
        targetType: 'cidr',
        effect: 'include',
        pattern: '198.51.100.0/24',
        ports: [443],
      },
    ]);
    const r = resolved(['198.51.100.10']);
    expect(
      run(portScoped, url('example.com', '/x', 'https'), active, r)
    ).toMatchObject({
      allowed: true,
      matchedRuleIds: ['r1', 'r2'],
    });
    expect(
      run(portScoped, url('example.com', '/x', 'http'), active, r)
    ).toMatchObject({
      allowed: false,
      reasons: ['RESOLVED_IP_OUT_OF_SCOPE'],
      matchedRuleIds: ['r2'],
    });
  });
});

describe('fixtures', () => {
  const compiled = compileScope(sampleScopeVersion);
  if (!compiled.ok) throw new Error(JSON.stringify(compiled.errors));
  const scope = compiled.scope;

  it.each([
    [name('example.com'), true, ['r-domain-apex']],
    [ip('2001:db8::1'), true, ['r-cidr6-included']],
    [
      name('api.example.com', { port: 443, protocol: 'https' }),
      true,
      ['r-wildcard-sub', 'r-domain-api-https'],
    ],
    [ip('203.0.113.5'), false, ['r-ip-excluded']],
    [ip('198.51.100.7'), false, ['r-cidr-excluded']],
    [url('example.com', '/admin'), false, ['r-url-admin']],
    [ip('192.0.2.1'), false, []],
  ])('target %#', (target, allowed, ruleIds) => {
    expect(run(scope, target)).toMatchObject({
      allowed,
      matchedRuleIds: ruleIds,
    });
  });
});

describe('purity', () => {
  it('is deterministic and works on frozen inputs', () => {
    const scope = build([
      { targetType: 'domain', effect: 'include', pattern: 'example.com' },
      { targetType: 'cidr', effect: 'include', pattern: '198.51.100.0/24' },
    ]);
    const target = Object.freeze(name('example.com'));
    const r = Object.freeze({
      ips: Object.freeze([ipHost('198.51.100.10')]),
      cnames: Object.freeze(['cdn.example.com']),
    });
    expect(evaluate(scope, target, active, r)).toStrictEqual(
      evaluate(scope, target, active, r)
    );
  });
});
