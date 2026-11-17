import { describe, expect, it } from 'vitest';
import { normalizeUrlPrefix } from '../url';

const INVALID = { ok: false, reason: 'INVALID_TARGET' };
const valid = (value: string) => ({ ok: true, value });

describe('normalizeUrlPrefix: valid', () => {
  it.each([
    // scheme, host, default ports
    ['HTTPS://EXAMPLE.com:443/admin', 'https://example.com/admin'],
    ['https://example.com', 'https://example.com/'],
    ['http://example.com:80/x', 'http://example.com/x'],
    ['http://example.com:443/x', 'http://example.com:443/x'],
    ['https://example.com:80/x', 'https://example.com:80/x'],
    ['https://example.com:8443/x', 'https://example.com:8443/x'],
    ['https://example.com./admin', 'https://example.com/admin'],
    ['https://münchen.de/x', 'https://xn--mnchen-3ya.de/x'],
    // IPs
    ['https://203.0.113.5/x', 'https://203.0.113.5/x'],
    ['http://203.0.113.5:80/', 'http://203.0.113.5/'],
    ['https://[2001:DB8::1]:8443/x', 'https://[2001:db8::1]:8443/x'],
    ['https://[2001:db8::1]:443/x', 'https://[2001:db8::1]/x'],
    ['https://[::ffff:10.0.0.1]/x', 'https://10.0.0.1/x'],
    // paths
    ['https://example.com/admin/', 'https://example.com/admin/'],
    ['https://example.com:8443/a/../b', 'https://example.com:8443/b'],
    ['https://example.com/../admin', 'https://example.com/admin'],
    ['https://example.com/a/./b', 'https://example.com/a/b'],
    ['https://example.com/a/b/..', 'https://example.com/a/'],
    // percent-encoding
    ['https://example.com/%61dmin', 'https://example.com/admin'],
    ['https://example.com/%2e%2e/admin', 'https://example.com/admin'],
    ['https://example.com/a/%2E/b', 'https://example.com/a/b'],
    ['https://example.com/%7Euser', 'https://example.com/~user'],
    ['https://example.com/%c3%bc', 'https://example.com/%C3%BC'],
    ['https://example.com/a%20b', 'https://example.com/a%20b'],
    ['https://example.com/a%252e', 'https://example.com/a%252e'], // double-encoded stays literal
  ])('%s -> %s', (input, expected) => {
    expect(normalizeUrlPrefix(input)).toEqual(valid(expected));
  });

  it.each([
    'HTTPS://EXAMPLE.com:443/admin',
    'https://example.com',
    'https://[2001:DB8::1]:8443/x',
    'https://[::ffff:10.0.0.1]/x',
    'https://example.com/%61dmin',
    'https://example.com/%c3%bc',
    'https://münchen.de/x',
  ])('is idempotent for %s', (input) => {
    const first = normalizeUrlPrefix(input);
    expect(first.ok).toBe(true);
    if (first.ok) expect(normalizeUrlPrefix(first.value)).toEqual(first);
  });

  it('keeps look-alike hosts distinct', () => {
    const result = normalizeUrlPrefix('https://ex\u0430mple.com/x'); // Cyrillic a
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).not.toContain('//example.com');
  });
});

describe('normalizeUrlPrefix: invalid', () => {
  it.each([
    // scheme
    'example.com/admin',
    'ftp://example.com/',
    'file:///etc/passwd',
    'javascript:alert(1)',
    '//example.com/x',
    'https:/example.com/x',
    'https://',
    'https:///x',
    // userinfo
    'https://user@example.com/',
    'https://user:pw@example.com/',
    'https://example.com@evil.com/',
    // ports
    'https://example.com:0/',
    'https://example.com:/',
    'https://example.com:08/',
    'https://example.com:65536/',
    'https://example.com:80:90/',
    'https://example.com:abc/',
    // hosts: the same cases normalizeDomain / normalizeIp reject
    'https://example\u3002com/',
    'https://exa\u200Bmple.com/',
    'https://a_b.com/',
    'https://*.example.com/',
    'https://127.1/',
    'https://0x7f.1/',
    'https://2130706433/',
    'https://010.0.0.1/',
    'https://[1.2.3.4]/',
    'https://[::1/',
    'https://::1/',
    'https://[::1]8443/',
    'https://[fe80::1%25eth0]/',
    // path structure
    'https://example.com//admin',
    'https://example.com/a//b',
    'https://example.com//',
    'https://example.com/a\\b',
    'https://example.com\\admin',
    'https://example.com/a;b',
    'https://example.com/..;/admin',
    // encoded separators and NUL
    'https://example.com/a%2fb',
    'https://example.com/a%2Fb',
    'https://example.com/a%5cb',
    'https://example.com/a%5Cb',
    'https://example.com/a%00b',
    'https://example.com/a%3bb',
    'https://example.com/a%zz',
    'https://example.com/a%',
    'https://example.com/a%2',
    // query, fragment, whitespace, control, non-ASCII
    'https://example.com/?x=1',
    'https://example.com/#x',
    'https://example.com/a b',
    ' https://example.com/',
    'https://example.com/\n',
    'https://example.com/\0',
    'https://example.com/\u00FC',
    // length
    `https://example.com/${'a'.repeat(2100)}`,
    '',
  ])('rejects %j', (input) => {
    expect(normalizeUrlPrefix(input)).toEqual(INVALID);
  });

  it.each([null, undefined, 42, {}, [], true])('rejects non-string %j', (input) => {
    expect(normalizeUrlPrefix(input)).toEqual(INVALID);
  });
});