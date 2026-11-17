import { normalizeIp } from './ip';
import { normalizeDomain } from './normalize';
import type { NormalizeResult } from './normalize';

const ok = (value: string): NormalizeResult => ({ ok: true, value });
const invalid = (): NormalizeResult => ({
  ok: false,
  reason: 'INVALID_TARGET',
});

const MAX_URL_LENGTH = 2048;
const SCHEME = /^(https?):\/\//i;
const PORT = /^[1-9][0-9]{0,4}$/; // no leading zeros, no port 0
const BAD_PERCENT = /%(?![0-9A-Fa-f]{2})/;
const ENCODED_BYTE = /%([0-9A-Fa-f]{2})/g;
const DEFAULT_PORT = { http: '80', https: '443' } as const;

// Encoded bytes with no safe canonical form: NUL, '/', ';', '\'.
// '/' and '\' change path structure after decoding, ';' starts a path parameter.
const FORBIDDEN_ENCODED = new Set([0x00, 0x2f, 0x3b, 0x5c]);

/** Whitespace/control characters and the delimiters a prefix rule must never contain. */
function hasForbiddenChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return true; // whitespace + control
    if (c === 0x5c) return true; // backslash
    if (c === 0x23 || c === 0x3f) return true; // '#' and '?'
    if (c === 0x3b) return true; // ';' path parameters
  }
  return false;
}

function isUnreserved(b: number): boolean {
  return (
    (b >= 0x30 && b <= 0x39) || // 0-9
    (b >= 0x41 && b <= 0x5a) || // A-Z
    (b >= 0x61 && b <= 0x7a) || // a-z
    b === 0x2d || // -
    b === 0x2e || // .
    b === 0x5f || // _
    b === 0x7e // ~
  );
}

function hasNonAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7f) return true;
  }
  return false;
}

/**
 * Decodes unreserved characters (%61 -> a, %2e -> .), uppercases the hex of
 * everything else (%c3 -> %C3), and rejects malformed or unsafe escapes.
 */
function canonicalizePercent(path: string): string | null {
  if (BAD_PERCENT.test(path)) return null;
  let bad = false;
  const out = path.replace(ENCODED_BYTE, (match, hex: string) => {
    const byte = parseInt(hex, 16);
    if (FORBIDDEN_ENCODED.has(byte)) {
      bad = true;
      return match;
    }
    return isUnreserved(byte) ? String.fromCharCode(byte) : `%${hex.toUpperCase()}`;
  });
  return bad ? null : out;
}

type Authority = { host: string; bracketed: boolean; port: string | null };

function splitAuthority(authority: string): Authority | null {
  if (authority.length === 0 || authority.includes('@')) return null; // no userinfo

  let host: string;
  let bracketed = false;
  let rest: string;

  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close === -1) return null;
    host = authority.slice(1, close);
    bracketed = true;
    rest = authority.slice(close + 1);
    if (rest !== '' && !rest.startsWith(':')) return null;
  } else {
    const first = authority.indexOf(':');
    if (first !== authority.lastIndexOf(':')) return null; // bare IPv6 or "a:80:90"
    host = first === -1 ? authority : authority.slice(0, first);
    rest = first === -1 ? '' : authority.slice(first);
  }

  let port: string | null = null;
  if (rest !== '') {
    port = rest.slice(1);
    if (!PORT.test(port) || Number(port) > 65535) return null;
  }
  return { host, bracketed, port };
}

/** Runs the host through the same normalizers used everywhere else. */
function normalizeHost(host: string, bracketed: boolean): string | null {
  if (bracketed) {
    if (!host.includes(':')) return null; // "[1.2.3.4]" is not valid
    const ip = normalizeIp(host);
    if (!ip.ok) return null;
    // An IPv4-mapped address collapses to IPv4, which is emitted unbracketed.
    return ip.value.includes(':') ? `[${ip.value}]` : ip.value;
  }
  const ip = normalizeIp(host);
  if (ip.ok) return ip.value;
  const domain = normalizeDomain(host);
  return domain.ok ? domain.value : null;
}

/**
 * Normalizes a URL prefix such as "https://example.com/admin".
 * Never throws; anything unsafe or ambiguous returns INVALID_TARGET.
 *
 * - Scheme: http or https only, lowercased.
 * - Host: normalizeDomain / normalizeIp (same rules as everywhere else).
 *   Bracketed IPv4-mapped IPv6 collapses to IPv4.
 * - Port: default ports (:80 for http, :443 for https) are dropped.
 * - Path: unreserved %-escapes decoded, other escapes uppercased, dot
 *   segments resolved. Rejected outright: userinfo, query, fragment, ';',
 *   '\', %2f, %5c, %00, %3b, empty segments ("//"), non-ASCII, whitespace.
 *
 * Prefix semantics (the matcher's job, recorded here so it stays consistent):
 * "/admin" covers "/admin" and "/admin/x" but not "/administrator".
 * Downstream code must use the returned value, never the raw input.
 */
export function normalizeUrlPrefix(rawInput: unknown): NormalizeResult {
  if (typeof rawInput !== 'string') return invalid();
  if (rawInput.length === 0 || rawInput.length > MAX_URL_LENGTH) return invalid();
  if (hasForbiddenChar(rawInput)) return invalid();

  const schemeMatch = SCHEME.exec(rawInput);
  const schemeRaw = schemeMatch?.[1];
  if (!schemeMatch || schemeRaw === undefined) return invalid();
  const scheme = schemeRaw.toLowerCase() as 'http' | 'https';

  const rest = rawInput.slice(schemeMatch[0].length);
  const slash = rest.indexOf('/');
  const authorityRaw = slash === -1 ? rest : rest.slice(0, slash);
  const pathRaw = slash === -1 ? '/' : rest.slice(slash);

  const authority = splitAuthority(authorityRaw);
  if (authority === null) return invalid();

  const host = normalizeHost(authority.host, authority.bracketed);
  if (host === null) return invalid();

  if (hasNonAscii(pathRaw)) return invalid(); // paths must arrive percent-encoded

  const decoded = canonicalizePercent(pathRaw);
  if (decoded === null) return invalid();

  // Empty interior segments ("//") are collapsed by many servers: reject.
  const segments = decoded.split('/');
  for (let i = 1; i < segments.length - 1; i++) {
    if (segments[i] === '') return invalid();
  }

  // The URL parser is used only to resolve dot segments and encode stray characters.
  let path: string;
  try {
    path = new URL(`http://example.com${decoded}`).pathname;
  } catch {
    return invalid();
  }

  const port =
    authority.port === null || authority.port === DEFAULT_PORT[scheme]
      ? ''
      : `:${authority.port}`;

  return ok(`${scheme}://${host}${port}${path}`);
}