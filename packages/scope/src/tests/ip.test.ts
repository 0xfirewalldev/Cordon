import { describe, expect, it } from 'vitest';
import { normalizeCidr, normalizeIp, parseCidr, parseIp } from '../ip';

const INVALID = { ok: false, reason: 'INVALID_TARGET' };
const valid = (value: string) => ({ ok: true, value });

describe('normalizeIp: valid', () => {
  it.each([
    // IPv4
    ['203.0.113.5', '203.0.113.5'],
    ['0.0.0.0', '0.0.0.0'],
    ['255.255.255.255', '255.255.255.255'],
    // IPv6 canonicalization
    ['2001:db8::1', '2001:db8::1'],
    ['2001:0DB8:0:0:0:0:0:1', '2001:db8::1'],
    ['2001:DB8::1', '2001:db8::1'],
    ['::1', '::1'],
    ['::', '::'],
    ['1:0:0:0:0:0:0:0', '1::'],
    ['2001:db8:0:0:1:0:0:1', '2001:db8::1:0:0:1'], // tie: first run wins
    ['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'], // single zero group not compressed
    ['1:2:3:4:5:6:1.2.3.4', '1:2:3:4:5:6:102:304'],
    ['64:ff9b::1.2.3.4', '64:ff9b::102:304'],
    // IPv4-mapped IPv6 collapses to IPv4
    ['::ffff:10.0.0.1', '10.0.0.1'],
    ['::ffff:a00:1', '10.0.0.1'],
    ['::FFFF:10.0.0.1', '10.0.0.1'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeIp(input)).toEqual(valid(expected));
  });

  it.each([
    '203.0.113.5',
    '2001:0DB8:0:0:0:0:0:1',
    '::ffff:10.0.0.1',
    '64:ff9b::1.2.3.4',
  ])('is idempotent for %s', (input) => {
    const first = normalizeIp(input);
    expect(first.ok).toBe(true);
    if (first.ok) expect(normalizeIp(first.value)).toEqual(first);
  });
});

describe('normalizeIp: invalid', () => {
  it.each([
    // IPv4 ambiguity and malformed
    '127.1',
    '2130706433',
    '0x7f.0.0.1',
    '0177.0.0.1',
    '010.0.0.1',
    '01.2.3.4',
    '256.1.1.1',
    '1.2.3',
    '1.2.3.4.5',
    '1.2.3.4.',
    '.1.2.3.4',
    '1..3.4',
    'a.b.c.d',
    '-1.2.3.4',
    '1.2.3.4:80',
    '\uFF11\uFF12\uFF17.\uFF10.\uFF10.\uFF11', // fullwidth digits
    // whitespace is rejected, not trimmed
    ' 1.2.3.4',
    '1.2.3.4 ',
    '1.2.3.4\n',
    '',
    // not IPs
    'example.com',
    'abc',
    // IPv6 malformed
    '2001:db8:::1',
    '12345::1',
    '1::2::3',
    '::g',
    '::ffff:999.0.0.1',
    ':1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7:8:9',
    '1::2:3:4:5:6:7:8',
    '1:2:3:4:5:6:7:1.2.3.4',
    '1.2.3.4::',
    // IPv6 extras we refuse
    'fe80::1%eth0',
    '[::1]',
    '::1.2.3.4', // deprecated IPv4-compatible form
    // length
    '1'.repeat(46),
  ])('rejects %j', (input) => {
    expect(normalizeIp(input)).toEqual(INVALID);
  });

  it.each([null, undefined, 42, {}, [], true])('rejects non-string %j', (input) => {
    expect(normalizeIp(input)).toEqual(INVALID);
  });
});

describe('parseIp', () => {
  it('returns the same numeric value for a mapped address and its IPv4 form', () => {
    expect(parseIp('::ffff:10.0.0.1')).toEqual(parseIp('10.0.0.1'));
  });

  it('reports the version', () => {
    expect(parseIp('10.0.0.1')?.version).toBe(4);
    expect(parseIp('2001:db8::1')?.version).toBe(6);
  });
});

describe('normalizeCidr: valid', () => {
  it.each([
    ['198.51.100.0/24', '198.51.100.0/24'],
    ['203.0.113.5/32', '203.0.113.5/32'],
    ['2001:db8::/32', '2001:db8::/32'],
    ['2001:0DB8::/32', '2001:db8::/32'],
    ['2001:db8::1/128', '2001:db8::1/128'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeCidr(input)).toEqual(valid(expected));
  });

  it('exposes network and prefix', () => {
    const c = parseCidr('198.51.100.0/24');
    expect(c).toMatchObject({ version: 4, prefix: 24 });
    expect(c?.network).toBe(parseIp('198.51.100.0')?.value);
  });
});

describe('normalizeCidr: invalid', () => {
  it.each([
    '10.0.0.1/24', // host bits set
    '2001:db8::1/32', // host bits set
    '10.0.0.0/33',
    '2001:db8::/129',
    '10.0.0.0/024',
    '10.0.0.0/-1',
    '10.0.0.0/',
    '/24',
    '10.0.0.0/24/8',
    '10.0.0.0',
    '10.0.0.0/ 24',
    ' 10.0.0.0/24',
    '0.0.0.0/0',
    '::/0',
    '::ffff:10.0.0.0/120', // write mapped ranges as IPv4 CIDRs
    'example.com/24',
    '127.1/8',
  ])('rejects %j', (input) => {
    expect(normalizeCidr(input)).toEqual(INVALID);
  });

  it.each([null, undefined, 24, {}])('rejects non-string %j', (input) => {
    expect(normalizeCidr(input)).toEqual(INVALID);
  });
});