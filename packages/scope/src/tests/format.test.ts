import { describe, expect, it } from 'vitest';
import { hostToString } from '../format';
import { parseTarget } from '../parse-target';

const host = (raw: string) => {
  const r = parseTarget(raw);
  if (!r.ok) throw new Error(r.message);
  return r.target.host;
};

describe('hostToString', () => {
  it.each([
    ['EXAMPLE.com', 'example.com'],
    ['example.com.', 'example.com'],
    ['203.0.113.5', '203.0.113.5'],
    ['2001:0DB8:0:0:0:0:0:1', '2001:db8::1'],
    ['[2001:DB8::1]:8443', '2001:db8::1'],
    ['::1', '::1'],
    ['::ffff:10.0.0.1', '10.0.0.1'],
    ['https://[::ffff:10.0.0.1]/x', '10.0.0.1'],
    ['https://Example.COM/x', 'example.com'],
  ])('%s -> %s', (raw, expected) => {
    expect(hostToString(host(raw))).toBe(expected);
  });

  it('round-trips: parsing the text gives the same host', () => {
    for (const raw of ['example.com', '203.0.113.5', '2001:db8::1', '::ffff:10.0.0.1', 'münchen.de']) {
      const h = host(raw);
      expect(host(hostToString(h))).toStrictEqual(h);
    }
  });
});