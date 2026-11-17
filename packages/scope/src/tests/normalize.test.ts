import { describe, expect, it } from 'vitest';
import {
  isValidAsciiHostname,
  normalizeDomain,
  normalizeWildcard,
} from '../normalize';

const INVALID = { ok: false, reason: 'INVALID_TARGET' };

const labels253 = [
  'a'.repeat(63),
  'b'.repeat(63),
  'c'.repeat(63),
  'd'.repeat(61),
].join('.');

describe('normalizeDomain: valid', () => {
  it.each([
    ['EXAMPLE.com', 'example.com'],
    ['Example.COM', 'example.com'],
    ['example.com.', 'example.com'],
    ['sub.example.com', 'sub.example.com'],
    ['localhost', 'localhost'],
    ['münchen.de', 'xn--mnchen-3ya.de'],
    ['xn--mnchen-3ya.de', 'xn--mnchen-3ya.de'],
    // matching is the matcher's job; normalization must not mangle this
    ['example.com.evil.com', 'example.com.evil.com'],
    [`${'a'.repeat(63)}.com`, `${'a'.repeat(63)}.com`],
    [labels253, labels253],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeDomain(input)).toEqual({ ok: true, value: expected });
  });

  it('turns a Cyrillic look-alike into a distinct punycode name', () => {
    const result = normalizeDomain('ex\u0430mple.com'); // Cyrillic a
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).not.toBe('example.com');
      expect(result.value.startsWith('xn--')).toBe(true);
    }
  });

  it.each(['EXAMPLE.com', 'münchen.de', 'example.com.', 'a.b.example.com'])(
    'is idempotent for %s',
    (input) => {
      const first = normalizeDomain(input);
      expect(first.ok).toBe(true);
      if (first.ok) expect(normalizeDomain(first.value)).toEqual(first);
    },
  );
});

describe('normalizeDomain: invalid', () => {
  it.each([
    // empty / dots
    '',
    '.',
    '..',
    'example.com..',
    '.example.com',
    'a..b.com',
    // look-alike dot and invisible characters
    'example\u3002com',
    'exa\u200Bmple.com',
    'exa\u00ADmple.com',
    // IP-shaped (decimal, hex, octal, shorthand, fullwidth)
    '127.1',
    '2130706433',
    '0x7f.1',
    '0177.0.0.1',
    '192.168.1.1',
    'foo.0xff',
    'foo.123',
    '\uFF11\uFF12\uFF17.\uFF10.\uFF10.\uFF11',
    // hyphens
    '-a.com',
    'a-.com',
    // forbidden characters
    'a_b.com',
    'a b.com',
    'a.com\n',
    'a\0.com',
    'a.com/x',
    'a@b.com',
    'a:80.com',
    'a?x.com',
    'a#x.com',
    'a\\b.com',
    'a%41.com',
    '[::1]',
    // wildcards belong to normalizeWildcard
    '*.example.com',
    'ex*.com',
    // lengths
    `${'a'.repeat(64)}.com`,
    `${labels253}.e`,
    'a'.repeat(2000),
    // Unicode label that is <= 63 chars raw but > 63 after punycode
    `${'\u65E5'.repeat(60)}.example.com`,
  ])('rejects %j', (input) => {
    expect(normalizeDomain(input)).toEqual(INVALID);
  });

  it.each([null, undefined, 42, {}, [], true])('rejects non-string %j', (input) => {
    expect(normalizeDomain(input)).toEqual(INVALID);
  });
});

describe('normalizeWildcard', () => {
  it.each([
    ['*.example.com', 'example.com'],
    ['*.EXAMPLE.com', 'example.com'],
    ['*.sub.example.com', 'sub.example.com'],
  ])('%s -> base %s', (input, expected) => {
    expect(normalizeWildcard(input)).toEqual({ ok: true, value: expected });
  });

  it.each([
    'example.com',
    '*',
    '*.',
    '*.com',
    '*.localhost',
    '*.*.example.com',
    '**.example.com',
    'ex*.com',
    '*example.com',
    '*..example.com',
    '*.example.com/x',
    '*.127.0.0.1',
  ])('rejects %j', (input) => {
    expect(normalizeWildcard(input)).toEqual(INVALID);
  });

  it.each([null, undefined, 42])('rejects non-string %j', (input) => {
    expect(normalizeWildcard(input)).toEqual(INVALID);
  });
});

describe('isValidAsciiHostname', () => {
  it.each(['example.com', 'xn--mnchen-3ya.de', 'a', 'a-b.example.com'])(
    'accepts %s',
    (host) => expect(isValidAsciiHostname(host)).toBe(true),
  );

  it.each(['', 'Example.com', 'a..b', '.a', 'a.', 'a_b.com', '-a.com', '1.2.3.4'])(
    'rejects %j',
    (host) => expect(isValidAsciiHostname(host)).toBe(false),
  );
});