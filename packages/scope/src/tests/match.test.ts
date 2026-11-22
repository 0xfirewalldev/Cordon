import { describe, expect, it } from 'vitest';
import { compileRule } from '../compile';
import type { CompiledRule } from '../compile';
import { parseIp } from '../ip';
import { evaluateExclude, evaluateInclude, matchTarget } from '../match';
import type { HostRef, MatchContext, Target } from '../target';
import type { RawRule } from '../types';

const ctx: MatchContext = { toolClass: 'passive' };

const compile = (raw: Omit<RawRule, 'id'>): CompiledRule => {
  const res = compileRule({ id: 'r', ...raw });
  if (!res.ok) throw new Error(res.message);
  return res.rule;
};

const hostRef = (s: string): HostRef => {
  const ip = parseIp(s);
  return ip
    ? { kind: 'ip', version: ip.version, value: ip.value }
    : { kind: 'name', name: s };
};

const host = (s: string, extra: Omit<Target, 'host'> = {}): Target => ({
  host: hostRef(s),
  ...extra,
});

const url = (
  s: string,
  path: string,
  scheme: 'http' | 'https' = 'https',
  port?: number
): Target => ({
  host: hostRef(s),
  url: { scheme, path },
  ...(port !== undefined ? { port } : {}),
});

describe('domain rules', () => {
  const rule = compile({
    targetType: 'domain',
    effect: 'include',
    pattern: 'example.com',
  });

  it('matches the exact host', () => {
    expect(matchTarget(rule, host('example.com'))).toBe(true);
  });

  it.each([
    'www.example.com',
    'example.org',
    'example.com.evil.com',
    'evilexample.com',
  ])('does not match %s', name =>
    expect(matchTarget(rule, host(name))).toBe(false)
  );

  it('does not match an IP target', () => {
    expect(matchTarget(rule, host('203.0.113.5'))).toBe(false);
  });

  it('applies at host level to a URL target', () => {
    expect(matchTarget(rule, url('example.com', '/anything'))).toBe(true);
  });
});

describe('wildcard rules', () => {
  const rule = compile({
    targetType: 'wildcard',
    effect: 'include',
    pattern: '*.example.com',
  });

  it.each(['a.example.com', 'a.b.example.com'])('matches %s', name =>
    expect(matchTarget(rule, host(name))).toBe(true)
  );

  it.each([
    'example.com',
    'evilexample.com',
    'example.com.evil.com',
    'xexample.com',
    'example.org',
  ])('does not match %s', name =>
    expect(matchTarget(rule, host(name))).toBe(false)
  );

  it('does not match an IP target', () => {
    expect(matchTarget(rule, host('203.0.113.5'))).toBe(false);
  });
});

describe('ip rules', () => {
  it('matches equal IPv4 and rejects a different one', () => {
    const rule = compile({
      targetType: 'ip',
      effect: 'include',
      pattern: '203.0.113.5',
    });
    expect(matchTarget(rule, host('203.0.113.5'))).toBe(true);
    expect(matchTarget(rule, host('203.0.113.6'))).toBe(false);
  });

  it('matches an IPv4-mapped IPv6 target against an IPv4 rule', () => {
    const rule = compile({
      targetType: 'ip',
      effect: 'exclude',
      pattern: '10.0.0.1',
    });
    expect(matchTarget(rule, host('::ffff:10.0.0.1'))).toBe(true);
  });

  it('matches equal IPv6', () => {
    const rule = compile({
      targetType: 'ip',
      effect: 'include',
      pattern: '2001:db8::1',
    });
    expect(matchTarget(rule, host('2001:0DB8:0:0:0:0:0:1'))).toBe(true);
    expect(matchTarget(rule, host('2001:db8::2'))).toBe(false);
  });

  it('never confuses versions that share a numeric value', () => {
    const v6 = compile({ targetType: 'ip', effect: 'include', pattern: '::1' }); // value 1n
    expect(matchTarget(v6, host('0.0.0.1'))).toBe(false); // value 1n, version 4
  });

  it('does not match a name target', () => {
    const rule = compile({
      targetType: 'ip',
      effect: 'include',
      pattern: '203.0.113.5',
    });
    expect(matchTarget(rule, host('example.com'))).toBe(false);
  });
});

describe('cidr rules', () => {
  it.each([
    ['198.51.100.0/24', '198.51.100.0', true],
    ['198.51.100.0/24', '198.51.100.255', true],
    ['198.51.100.0/24', '198.51.99.255', false],
    ['198.51.100.0/24', '198.51.101.0', false],
    ['10.0.0.0/8', '10.255.255.255', true],
    ['10.0.0.0/8', '11.0.0.0', false],
    ['203.0.113.5/32', '203.0.113.5', true],
    ['203.0.113.5/32', '203.0.113.6', false],
    ['2001:db8::/32', '2001:db8::1', true],
    ['2001:db8::/32', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', true],
    ['2001:db8::/32', '2001:db9::', false],
  ])('%s contains %s: %s', (cidr, addr, expected) => {
    const rule = compile({
      targetType: 'cidr',
      effect: 'include',
      pattern: cidr,
    });
    expect(matchTarget(rule, host(addr))).toBe(expected);
  });

  it('does not match across IP versions', () => {
    const v4 = compile({
      targetType: 'cidr',
      effect: 'include',
      pattern: '10.0.0.0/8',
    });
    expect(matchTarget(v4, host('::a00:1'))).toBe(false);
  });

  it('does not match a name target', () => {
    const rule = compile({
      targetType: 'cidr',
      effect: 'include',
      pattern: '10.0.0.0/8',
    });
    expect(matchTarget(rule, host('example.com'))).toBe(false);
  });

  it('applies at host level to a URL target with an IP host', () => {
    const rule = compile({
      targetType: 'cidr',
      effect: 'exclude',
      pattern: '198.51.100.0/24',
    });
    expect(matchTarget(rule, url('198.51.100.7', '/x'))).toBe(true);
  });
});

describe('url_prefix include rules', () => {
  const rule = compile({
    targetType: 'url_prefix',
    effect: 'include',
    pattern: 'https://example.com/admin',
  });

  it.each([
    ['/admin', true],
    ['/admin/', true],
    ['/admin/users', true],
    ['/administrator', false],
    ['/admin2', false],
    ['/', false],
    ['/other/admin', false],
    ['/Admin', false],
  ])('path %s: %s', (path, expected) => {
    expect(matchTarget(rule, url('example.com', path))).toBe(expected);
  });

  it('requires the same scheme, effective port and host', () => {
    expect(matchTarget(rule, url('example.com', '/admin', 'https', 443))).toBe(
      true
    );
    expect(matchTarget(rule, url('example.com', '/admin', 'http'))).toBe(false);
    expect(matchTarget(rule, url('example.com', '/admin', 'https', 8443))).toBe(
      false
    );
    expect(matchTarget(rule, url('www.example.com', '/admin'))).toBe(false);
  });

  it('does not match a host-only target', () => {
    expect(matchTarget(rule, host('example.com'))).toBe(false);
  });

  it('a root path covers everything on that origin', () => {
    const root = compile({
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://example.com/',
    });
    expect(matchTarget(root, url('example.com', '/'))).toBe(true);
    expect(matchTarget(root, url('example.com', '/a/b'))).toBe(true);
  });

  it('treats a trailing slash on the rule as insignificant', () => {
    const slash = compile({
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://example.com/admin/',
    });
    expect(matchTarget(slash, url('example.com', '/admin'))).toBe(true);
    expect(matchTarget(slash, url('example.com', '/admin/x'))).toBe(true);
    expect(matchTarget(slash, url('example.com', '/administrator'))).toBe(
      false
    );
  });

  it('matches IP hosts numerically, not by string', () => {
    const v4 = compile({
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://203.0.113.5/x',
    });
    expect(matchTarget(v4, url('203.0.113.5', '/x'))).toBe(true);
    expect(matchTarget(v4, url('203.0.113.6', '/x'))).toBe(false);
    expect(matchTarget(v4, url('example.com', '/x'))).toBe(false);

    const v6 = compile({
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://[2001:db8::1]/x',
    });
    expect(matchTarget(v6, url('2001:DB8::1', '/x'))).toBe(true);

    const mapped = compile({
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://[::ffff:10.0.0.1]/x',
    });
    expect(matchTarget(mapped, url('10.0.0.1', '/x'))).toBe(true);
  });
});

describe('url_prefix exclude rules fail safe', () => {
  const rule = compile({
    targetType: 'url_prefix',
    effect: 'exclude',
    pattern: 'https://example.com/admin',
  });

  it.each([
    [url('example.com', '/admin', 'http'), true], // scheme ignored
    [url('example.com', '/admin', 'https', 8443), true], // port ignored
    [url('example.com', '/ADMIN'), true], // case-insensitive
    [url('example.com', '/Admin/x'), true],
    [url('example.com', '/administrator'), false], // segment boundary still holds
    [url('example.com', '/other'), false],
    [url('www.example.com', '/admin'), false],
    [host('example.com'), false], // host-only targets are re-checked per URL by the gate
  ])('target %#', (target, expected) => {
    expect(matchTarget(rule, target)).toBe(expected);
  });
});

describe('unknown rule types fail closed', () => {
  const base = compile({
    targetType: 'domain',
    effect: 'include',
    pattern: 'example.com',
  });

  it('an unknown exclude applies, an unknown include does not', () => {
    const bogusExclude = {
      ...base,
      effect: 'exclude',
      targetType: 'bogus',
    } as unknown as CompiledRule;
    const bogusInclude = {
      ...base,
      targetType: 'bogus',
    } as unknown as CompiledRule;
    expect(matchTarget(bogusExclude, host('example.com'))).toBe(true);
    expect(matchTarget(bogusInclude, host('example.com'))).toBe(false);
  });
});

describe('evaluateInclude: constraints', () => {
  it('allows when there are no constraints', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
    });
    expect(evaluateInclude(rule, host('example.com'), ctx)).toStrictEqual({
      status: 'allowed',
    });
  });

  it('ports: matches, mismatches, and fails closed when the port is unknown', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      ports: [443],
    });
    expect(
      evaluateInclude(rule, host('example.com', { port: 443 }), ctx)
    ).toStrictEqual({ status: 'allowed' });
    expect(
      evaluateInclude(rule, host('example.com', { port: 80 }), ctx)
    ).toStrictEqual({
      status: 'constrained',
      reason: 'PORT_NOT_ALLOWED',
    });
    expect(evaluateInclude(rule, host('example.com'), ctx)).toStrictEqual({
      status: 'constrained',
      reason: 'PORT_NOT_ALLOWED',
    });
  });

  it('ports: URL targets use the effective port from the scheme', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      ports: [443],
    });
    expect(
      evaluateInclude(rule, url('example.com', '/x', 'https'), ctx)
    ).toStrictEqual({ status: 'allowed' });
    expect(
      evaluateInclude(rule, url('example.com', '/x', 'http'), ctx)
    ).toStrictEqual({
      status: 'constrained',
      reason: 'PORT_NOT_ALLOWED',
    });
  });

  it('protocols: matches, mismatches, derives from the URL scheme, fails closed when unknown', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      protocols: ['https'],
    });
    expect(
      evaluateInclude(rule, host('example.com', { protocol: 'https' }), ctx)
    ).toStrictEqual({ status: 'allowed' });
    expect(
      evaluateInclude(rule, host('example.com', { protocol: 'ssh' }), ctx)
    ).toStrictEqual({
      status: 'constrained',
      reason: 'PROTOCOL_NOT_ALLOWED',
    });
    expect(evaluateInclude(rule, host('example.com'), ctx)).toStrictEqual({
      status: 'constrained',
      reason: 'PROTOCOL_NOT_ALLOWED',
    });
    expect(
      evaluateInclude(rule, url('example.com', '/x', 'https'), ctx)
    ).toStrictEqual({ status: 'allowed' });
    expect(
      evaluateInclude(rule, url('example.com', '/x', 'http'), ctx)
    ).toStrictEqual({
      status: 'constrained',
      reason: 'PROTOCOL_NOT_ALLOWED',
    });
  });

  it('toolClasses: restricts by the context tool class', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      toolClasses: ['passive'],
    });
    expect(
      evaluateInclude(rule, host('example.com'), { toolClass: 'passive' })
    ).toStrictEqual({ status: 'allowed' });
    expect(
      evaluateInclude(rule, host('example.com'), { toolClass: 'active-light' })
    ).toStrictEqual({
      status: 'constrained',
      reason: 'TOOL_CLASS_NOT_ALLOWED',
    });
  });

  it('reports constraints in a fixed order: port, protocol, tool class', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      ports: [443],
      protocols: ['https'],
      toolClasses: ['passive'],
    });
    const active: MatchContext = { toolClass: 'active-light' };
    expect(
      evaluateInclude(
        rule,
        host('example.com', { port: 80, protocol: 'ssh' }),
        active
      )
    ).toStrictEqual({
      status: 'constrained',
      reason: 'PORT_NOT_ALLOWED',
    });
    expect(
      evaluateInclude(
        rule,
        host('example.com', { port: 443, protocol: 'ssh' }),
        active
      )
    ).toStrictEqual({
      status: 'constrained',
      reason: 'PROTOCOL_NOT_ALLOWED',
    });
    expect(
      evaluateInclude(
        rule,
        host('example.com', { port: 443, protocol: 'https' }),
        active
      )
    ).toStrictEqual({
      status: 'constrained',
      reason: 'TOOL_CLASS_NOT_ALLOWED',
    });
  });

  it('a rule that does not cover the target is no_match, whatever its constraints', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      ports: [443],
    });
    expect(
      evaluateInclude(rule, host('other.com', { port: 80 }), ctx)
    ).toStrictEqual({ status: 'no_match' });
  });

  it('ignores exclude rules', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'exclude',
      pattern: 'example.com',
    });
    expect(evaluateInclude(rule, host('example.com'), ctx)).toStrictEqual({
      status: 'no_match',
    });
  });
});

describe('evaluateExclude: constraints', () => {
  const ssh = compile({
    targetType: 'ip',
    effect: 'exclude',
    pattern: '203.0.113.5',
    ports: [22],
  });

  it('applies on the constrained port, releases other ports, and applies when the port is unknown', () => {
    expect(evaluateExclude(ssh, host('203.0.113.5', { port: 22 }), ctx)).toBe(
      true
    );
    expect(evaluateExclude(ssh, host('203.0.113.5', { port: 443 }), ctx)).toBe(
      false
    );
    expect(evaluateExclude(ssh, host('203.0.113.5'), ctx)).toBe(true);
  });

  it('does not apply to a different address', () => {
    expect(evaluateExclude(ssh, host('203.0.113.6', { port: 22 }), ctx)).toBe(
      false
    );
  });

  it('protocols: releases a known mismatch, applies when unknown', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'exclude',
      pattern: 'example.com',
      protocols: ['ssh'],
    });
    expect(
      evaluateExclude(rule, host('example.com', { protocol: 'ssh' }), ctx)
    ).toBe(true);
    expect(
      evaluateExclude(rule, host('example.com', { protocol: 'http' }), ctx)
    ).toBe(false);
    expect(evaluateExclude(rule, host('example.com'), ctx)).toBe(true);
  });

  it('toolClasses: applies only to the listed classes', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'exclude',
      pattern: 'example.com',
      toolClasses: ['active-intrusive'],
    });
    expect(
      evaluateExclude(rule, host('example.com'), {
        toolClass: 'active-intrusive',
      })
    ).toBe(true);
    expect(
      evaluateExclude(rule, host('example.com'), { toolClass: 'passive' })
    ).toBe(false);
  });

  it('ignores include rules', () => {
    const rule = compile({
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
    });
    expect(evaluateExclude(rule, host('example.com'), ctx)).toBe(false);
  });
});
