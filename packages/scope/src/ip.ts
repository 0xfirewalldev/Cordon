import type { NormalizeResult } from './normalize';

const ok = (value: string): NormalizeResult => ({ ok: true, value });
const invalid = (): NormalizeResult => ({
  ok: false,
  reason: 'INVALID_TARGET',
});

const MAX_IP_LENGTH = 45; // longest textual IPv6 form (embedded IPv4)
const IPV4_OCTET = /^(0|[1-9][0-9]{0,2})$/; // no leading zeros: "010" is octal to some tools
const IPV6_RAW = /^[0-9a-fA-F:.]+$/;
const HEXTET = /^[0-9a-fA-F]{1,4}$/;
const PREFIX = /^(0|[1-9][0-9]{0,2})$/;

export type ParsedIp = { version: 4 | 6; value: bigint };

export type ParsedCidr = {
  version: 4 | 6;
  network: bigint;
  prefix: number;
  canonical: string;
};

function parseIpv4(raw: string): bigint | null {
  const parts = raw.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!IPV4_OCTET.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function toHextets(groups: string[], allowV4Last: boolean): number[] | null {
  const out: number[] = [];
  for (let i = 0; i < groups.length; i++) {
    const g = groups[i]!;
    if (g.includes('.')) {
      // An embedded IPv4 is only legal as the final element of the address.
      if (!allowV4Last || i !== groups.length - 1) return null;
      const v4 = parseIpv4(g);
      if (v4 === null) return null;
      out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
    } else {
      if (!HEXTET.test(g)) return null;
      out.push(parseInt(g, 16));
    }
  }
  return out;
}

function parseIpv6(raw: string): bigint | null {
  if (!IPV6_RAW.test(raw)) return null;

  const dbl = raw.indexOf('::');
  if (dbl !== raw.lastIndexOf('::')) return null; // more than one "::" (also catches ":::")

  let hextets: number[];
  if (dbl === -1) {
    const all = toHextets(raw.split(':'), true);
    if (all === null || all.length !== 8) return null;
    hextets = all;
  } else {
    const head = raw.slice(0, dbl);
    const tail = raw.slice(dbl + 2);
    const h = toHextets(head === '' ? [] : head.split(':'), false);
    const t = toHextets(tail === '' ? [] : tail.split(':'), true);
    if (h === null || t === null) return null;
    const zeros = 8 - h.length - t.length;
    if (zeros < 1) return null; // "::" must stand for at least one group
    hextets = [...h, ...new Array<number>(zeros).fill(0), ...t];
  }

  let value = 0n;
  for (const x of hextets) value = (value << 16n) | BigInt(x);
  return value;
}

function formatIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n]
    .map((shift) => String(Number((value >> shift) & 0xffn)))
    .join('.');
}

/** RFC 5952: lowercase, no leading zeros, longest zero run (>= 2 groups, first on ties) compressed. */
function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) {
    groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  }

  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }

  const hex = (n: number) => n.toString(16);
  if (bestLen < 2) return groups.map(hex).join(':');
  const left = groups.slice(0, bestStart).map(hex).join(':');
  const right = groups.slice(bestStart + bestLen).map(hex).join(':');
  return `${left}::${right}`;
}

/**
 * Strict IP parser. Never throws; returns null for anything ambiguous.
 * - IPv4: exactly four decimal octets, no leading zeros, no shorthand/hex/octal.
 * - IPv6: RFC 4291 text forms only. No zone IDs, no brackets.
 * - IPv4-mapped IPv6 (::ffff:a.b.c.d) is returned as the IPv4 address, so an
 *   IPv6 spelling can't dodge an IPv4 exclude rule.
 * - IPv4-compatible IPv6 (::a.b.c.d, deprecated) is rejected.
 */
export function parseIp(rawInput: unknown): ParsedIp | null {
  if (typeof rawInput !== 'string') return null;
  if (rawInput.length === 0 || rawInput.length > MAX_IP_LENGTH) return null;

  if (rawInput.includes(':')) {
    const v6 = parseIpv6(rawInput);
    if (v6 === null) return null;
    if (v6 >> 32n === 0xffffn) return { version: 4, value: v6 & 0xffffffffn };
    if (v6 >> 32n === 0n && v6 > 1n) return null; // keep :: and ::1, drop ::a.b.c.d
    return { version: 6, value: v6 };
  }

  const v4 = parseIpv4(rawInput);
  return v4 === null ? null : { version: 4, value: v4 };
}

/** Canonical string form: dotted IPv4, or lowercase compressed IPv6. */
export function normalizeIp(rawInput: unknown): NormalizeResult {
  const ip = parseIp(rawInput);
  if (ip === null) return invalid();
  return ok(ip.version === 4 ? formatIpv4(ip.value) : formatIpv6(ip.value));
}

/**
 * Strict CIDR parser.
 * - Rejects host bits set (10.0.0.1/24): silently masking could widen scope.
 * - Rejects /0 (would put the entire address space in scope).
 * - Rejects IPv4-mapped IPv6 CIDRs: write those as IPv4 CIDRs.
 */
export function parseCidr(rawInput: unknown): ParsedCidr | null {
  if (typeof rawInput !== 'string' || rawInput.length > MAX_IP_LENGTH + 4) {
    return null;
  }
  const parts = rawInput.split('/');
  if (parts.length !== 2) return null;
  const [addr, prefixRaw] = parts;
  if (addr === undefined || prefixRaw === undefined) return null;
  if (!PREFIX.test(prefixRaw)) return null;

  const ip = parseIp(addr);
  if (ip === null) return null;
  if (addr.includes(':') && ip.version === 4) return null;

  const bits = ip.version === 4 ? 32 : 128;
  const prefix = Number(prefixRaw);
  if (prefix === 0 || prefix > bits) return null;

  const hostMask = (1n << BigInt(bits - prefix)) - 1n;
  if ((ip.value & hostMask) !== 0n) return null;

  const base = ip.version === 4 ? formatIpv4(ip.value) : formatIpv6(ip.value);
  return {
    version: ip.version,
    network: ip.value,
    prefix,
    canonical: `${base}/${prefix}`,
  };
}

export function normalizeCidr(rawInput: unknown): NormalizeResult {
  const cidr = parseCidr(rawInput);
  return cidr === null ? invalid() : ok(cidr.canonical);
}