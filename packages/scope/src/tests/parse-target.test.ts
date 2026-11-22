import { describe, expect, it } from 'vitest';
import { sampleScopeVersion } from '../__fixtures__/rules';
import { compileScope } from '../compile';
import { evaluate } from '../evaluate';
import { parseIp } from '../ip';
import { parseTarget } from '../parse-target';
import type { IpHost, ToolClass } from '../target';

const ipHost = (s: string): IpHost => {
  const ip = parseIp(s);
  if (ip === null) throw new Error(`bad ip ${s}`);
  return { kind: 'ip', version: ip.version, value: ip.value };
};
const name = (n: string) => ({ kind: 'name' as const, name: n });

const good = (raw: unknown, resolution?: unknown) => {
  const r = parseTarget(raw, resolution);
  if (!r.ok) throw new Error(r.message);
  return r;
};

const INVALID = { ok: false, reason: 'INVALID_TARGET' };

describe('parseTarget: valid targets', () => {
  it.each([
    ['example.com', { host: name('example.com') }],
    ['EXAMPLE.com', { host: name('example.com') }],
    ['example.com.', { host: name('example.com') }],
    ['EXAMPLE.com:8443', { host: name('example.com'), port: 8443 }],
    ['203.0.113.5', { host: ipHost('203.0.113.5') }],
    ['203.0.113.5:8080', { host: ipHost('203.0.113.5'), port: 8080 }],
    ['2001:db8::1', { host: ipHost('2001:db8::1') }],
    // a port on IPv6 requires brackets: this is an address, not host and port
    ['2001:db8::1:8080', { host: ipHost('2001:db8::1:8080') }],
    ['[2001:db8::1]', { host: ipHost('2001:db8::1') }],
    ['[2001:db8::1]:8443', { host: ipHost('2001:db8::1'), port: 8443 }],
    // mapped IPv6 collapses to IPv4
    ['::ffff:10.0.0.1', { host: ipHost('10.0.0.1') }],
    ['[::ffff:10.0.0.1]', { host: ipHost('10.0.0.1') }],
  ])('%s', (raw, expected) => {
    expect(good(raw).target).toStrictEqual(expected);
  });

  it.each([
    [
      'https://Example.com:443/a/../b',
      {
        host: name('example.com'),
        port: 443,
        protocol: 'https',
        url: { scheme: 'https', path: '/b' },
      },
    ],
    [
      'http://example.com:8080/x',
      {
        host: name('example.com'),
        port: 8080,
        protocol: 'http',
        url: { scheme: 'http', path: '/x' },
      },
    ],
    [
      'http://[2001:db8::1]/x',
      {
        host: ipHost('2001:db8::1'),
        port: 80,
        protocol: 'http',
        url: { scheme: 'http', path: '/x' },
      },
    ],
    [
      'https://[::ffff:10.0.0.1]/x',
      {
        host: ipHost('10.0.0.1'),
        port: 443,
        protocol: 'https',
        url: { scheme: 'https', path: '/x' },
      },
    ],
    [
      'https://203.0.113.5',
      {
        host: ipHost('203.0.113.5'),
        port: 443,
        protocol: 'https',
        url: { scheme: 'https', path: '/' },
      },
    ],
  ])('URL %s', (raw, expected) => {
    expect(good(raw).target).toStrictEqual(expected);
  });

  it('returns no resolution when none is supplied', () => {
    expect('resolution' in good('example.com')).toBe(false);
  });

  it('freezes the target', () => {
    const { target } = good('https://example.com/x');
    expect(Object.isFrozen(target)).toBe(true);
    expect(Object.isFrozen(target.host)).toBe(true);
    expect(Object.isFrozen(target.url)).toBe(true);
  });
});

describe('parseTarget: invalid targets', () => {
  it.each([
    '',
    ' example.com',
    'example.com ',
    'example.com\n',
    // brackets only around IPv6
    '[example.com]',
    '[10.0.0.1]',
    '[::1',
    '[::1]8443',
    '[::1]:0',
    '[::1]:',
    // ports
    'example.com:',
    'example.com:0',
    'example.com:08',
    'example.com:65536',
    'example.com:80:90',
    '2001:db8::zz',
    // structure and forbidden characters
    'user@example.com',
    'example.com/admin',
    '*.example.com',
    '10.0.0.0/8',
    'a_b.com',
    // IP shorthand
    '127.1',
    '2130706433',
    '0x7f.0.0.1',
    // schemes and URL parts
    'ftp://example.com',
    'javascript:alert(1)',
    'https://',
    'https://user@example.com/',
    // queries and fragments are rejected: see the note on normalizeUrlTarget
    'https://example.com/?x=1',
    'https://example.com/#x',
  ])('rejects %j', (raw) => {
    expect(parseTarget(raw)).toMatchObject(INVALID);
  });

  it.each([null, undefined, 42, {}, [], true])('rejects non-string %j', (raw) => {
    expect(parseTarget(raw)).toMatchObject(INVALID);
  });

  it('rejects an oversized target without parsing it', () => {
    expect(parseTarget('a'.repeat(3000))).toMatchObject(INVALID);
  });

  it('produces escaped, bounded messages', () => {
    const withNewline = parseTarget('example.com\n');
    expect(withNewline.ok).toBe(false);
    if (!withNewline.ok) {
      expect(withNewline.message).not.toMatch(/\n/);
      expect(withNewline.message).toContain('\\n');
    }

    const long = parseTarget(`${'a'.repeat(100)}:99999`);
    expect(long.ok).toBe(false);
    if (!long.ok) expect(long.message.length).toBeLessThan(140);
  });
});

describe('parseTarget: resolution', () => {
  it('accepts the array form', () => {
    expect(good('example.com', ['198.51.100.10']).resolution).toStrictEqual({
      ips: [ipHost('198.51.100.10')],
      cnames: [],
    });
  });

  it('accepts the object form and normalizes CNAMEs', () => {
    expect(
      good('example.com', {
        ips: ['198.51.100.10', '2001:DB8::1'],
        cnames: ['CDN.Example.com.'],
      }).resolution,
    ).toStrictEqual({
      ips: [ipHost('198.51.100.10'), ipHost('2001:db8::1')],
      cnames: ['cdn.example.com'],
    });
  });

  it('collapses a mapped IPv6 string to IPv4', () => {
    expect(good('example.com', ['::ffff:10.0.0.1']).resolution?.ips).toStrictEqual([
      ipHost('10.0.0.1'),
    ]);
  });

  it('keeps an empty resolution distinct from none', () => {
    expect(good('example.com', []).resolution).toStrictEqual({ ips: [], cnames: [] });
    expect(good('example.com', {}).resolution).toStrictEqual({ ips: [], cnames: [] });
  });

  it('freezes the resolution', () => {
    const { resolution } = good('example.com', {
      ips: ['198.51.100.10'],
      cnames: ['cdn.example.com'],
    });
    expect(Object.isFrozen(resolution)).toBe(true);
    expect(Object.isFrozen(resolution?.ips)).toBe(true);
    expect(Object.isFrozen(resolution?.cnames)).toBe(true);
  });

  it.each([
    ['not an array or object', 'string'],
    ['null', null],
    ['a number', 42],
    ['ips as a string', { ips: '1.2.3.4' }],
    ['ips as null', { ips: null }],
    ['cnames as a string', { cnames: 'x.example.com' }],
    ['an unknown key', { ips: [], extra: 1 }],
    ['a non-string IP', [1]],
    ['a pre-built IpHost object', [{ kind: 'ip', version: 4, value: 1n }]],
    ['an invalid IP', ['not-an-ip']],
    ['IP shorthand', ['127.1']],
    ['a non-string CNAME', { cnames: [1] }],
    ['an invalid CNAME', { cnames: ['bad_name.com'] }],
    ['an IP as a CNAME', { cnames: ['1.2.3.4'] }],
    ['a sparse array', [, '198.51.100.10']],
  ])('rejects %s', (_label, resolution) => {
    expect(parseTarget('example.com', resolution)).toMatchObject(INVALID);
  });

  it('enforces the bounds exactly', () => {
    const ips = (n: number) => Array.from({ length: n }, () => '198.51.100.10');
    const cnames = (n: number) => Array.from({ length: n }, () => 'cdn.example.com');
    expect(parseTarget('example.com', ips(64)).ok).toBe(true);
    expect(parseTarget('example.com', ips(65))).toMatchObject(INVALID);
    expect(parseTarget('example.com', { cnames: cnames(16) }).ok).toBe(true);
    expect(parseTarget('example.com', { cnames: cnames(17) })).toMatchObject(INVALID);
  });

  it('escapes the values it reports', () => {
    const r = parseTarget('example.com', ['bad\nip']);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).not.toMatch(/\n/);
  });
});

describe('parseTarget into evaluate', () => {
  const compiled = compileScope(sampleScopeVersion);
  if (!compiled.ok) throw new Error(JSON.stringify(compiled.errors));
  const scope = compiled.scope;
  const NOW = Date.UTC(2026, 5, 1);

  const decide = (raw: string, toolClass: ToolClass = 'passive', resolution?: unknown) => {
    const parsed = good(raw, resolution);
    return evaluate(scope, parsed.target, { now: NOW, toolClass }, parsed.resolution);
  };

  it.each([
    ['example.com', true, ['r-domain-apex']],
    ['[2001:db8::1]:8443', true, ['r-cidr6-included']],
    ['203.0.113.5', false, ['r-ip-excluded']],
    ['::ffff:203.0.113.5', false, ['r-ip-excluded']],
    ['https://example.com/admin', false, ['r-url-admin']],
    ['192.0.2.1', false, []],
  ])('%s', (raw, allowed, ruleIds) => {
    expect(decide(raw)).toMatchObject({ allowed, matchedRuleIds: ruleIds });
  });

  it('an active tool with no resolution is denied', () => {
    expect(decide('example.com', 'active-light')).toMatchObject({
      allowed: false,
      reasons: ['RESOLUTION_REQUIRED'],
    });
  });

  it('a resolved hop inside an excluded range is denied', () => {
    expect(decide('example.com', 'active-light', ['198.51.100.10'])).toMatchObject({
      allowed: false,
      reasons: ['RESOLVED_IP_OUT_OF_SCOPE'],
      matchedRuleIds: ['r-cidr-excluded'],
    });
  });
});