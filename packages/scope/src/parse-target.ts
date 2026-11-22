import { parseIp } from './ip';
import { normalizeDomain } from './normalize';
import type { HostRef, Resolution, Target } from './target';
import { normalizeUrlPrefix } from './url';
import { show } from './util';

export type ParseTargetResult =
  | {
      readonly ok: true;
      readonly target: Target;
      readonly resolution?: Resolution;
    }
  | {
      readonly ok: false;
      readonly reason: 'INVALID_TARGET';
      readonly message: string;
    };

const MAX_TARGET_LENGTH = 2048;
const MAX_RESOLVED_IPS = 64;
const MAX_CNAMES = 16;
const PORT = /^[1-9][0-9]{0,4}$/; // no leading zeros, no port 0
const URL_SCHEME = /^https?:\/\//i;
// Characters that never belong in a host or host:port target.
const FORBIDDEN_IN_PLAIN_TARGET = /[\s/\\?#@]/;

const fail = (message: string): ParseTargetResult => ({
  ok: false,
  reason: 'INVALID_TARGET',
  message,
});

function parsePort(s: string): number | null {
  if (!PORT.test(s)) return null;
  const port = Number(s);
  return port <= 65535 ? port : null;
}

/** The single place a host string becomes a HostRef: IP first, then domain. */
function toHostRef(host: string): HostRef | null {
  const ip = parseIp(host);
  if (ip !== null) {
    return Object.freeze({
      kind: 'ip' as const,
      version: ip.version,
      value: ip.value,
    });
  }
  const name = normalizeDomain(host);
  return name.ok
    ? Object.freeze({ kind: 'name' as const, name: name.value })
    : null;
}

/** Returns a Target, or a message describing why the input was rejected. */
function parseUrlTarget(raw: string): Target | string {
  const norm = normalizeUrlPrefix(raw);
  if (!norm.ok) return `Invalid URL target ${show(raw)}`;

  let u: URL;
  try {
    u = new URL(norm.value);
  } catch {
    return 'URL failed to re-parse after normalization';
  }

  const scheme = u.protocol === 'https:' ? 'https' : 'http';
  const port = u.port !== '' ? Number(u.port) : scheme === 'https' ? 443 : 80;
  // IPv6 hosts keep their brackets in URL.hostname.
  const hostname = u.hostname.startsWith('[')
    ? u.hostname.slice(1, -1)
    : u.hostname;
  const host = toHostRef(hostname);
  if (host === null) return 'URL host failed to re-validate after normalization';

  return Object.freeze({
    host,
    port,
    protocol: scheme,
    url: Object.freeze({ scheme, path: u.pathname }),
  });
}

/**
 * host, host:port, bare IPv4/IPv6, or [IPv6] / [IPv6]:port.
 * A port on an IPv6 address requires brackets: "2001:db8::1:8080" is an
 * address, not host and port.
 */
function parsePlainTarget(raw: string): Target | string {
  if (FORBIDDEN_IN_PLAIN_TARGET.test(raw)) {
    return `Invalid target ${show(raw)}`;
  }

  let hostPart = raw;
  let port: number | undefined;

  if (raw.startsWith('[')) {
    const close = raw.indexOf(']');
    if (close === -1) return `Unclosed bracket in target ${show(raw)}`;
    hostPart = raw.slice(1, close);
    // Brackets are only valid around an IPv6 address, same as in URLs.
    if (!hostPart.includes(':')) {
      return 'Brackets are only valid around an IPv6 address';
    }
    const rest = raw.slice(close + 1);
    if (rest !== '') {
      if (!rest.startsWith(':')) {
        return `Malformed port separator in target ${show(raw)}`;
      }
      const parsed = parsePort(rest.slice(1));
      if (parsed === null) return `Invalid port in target ${show(raw)}`;
      port = parsed;
    }
  } else if (parseIp(raw) === null) {
    // Not a bare IP, so a trailing ":port" may be present.
    const colon = raw.lastIndexOf(':');
    if (colon !== -1) {
      hostPart = raw.slice(0, colon);
      const parsed = parsePort(raw.slice(colon + 1));
      if (parsed === null) return `Invalid port in target ${show(raw)}`;
      port = parsed;
    }
  }

  const host = toHostRef(hostPart);
  if (host === null) return `Invalid host in target ${show(raw)}`;
  return Object.freeze({
    host,
    ...(port !== undefined ? { port } : {}),
  });
}

type ParsedResolution =
  | { readonly ok: true; readonly resolution: Resolution }
  | { readonly ok: false; readonly message: string };

/**
 * Accepts an array of IP strings, or { ips?, cnames? } with string arrays.
 * Strings only: the engine never trusts pre-built host objects. Malformed
 * shapes are rejected, never treated as empty, because an empty resolution
 * would skip every hop check.
 */
function parseResolution(raw: unknown): ParsedResolution {
  const bad = (message: string): ParsedResolution => ({ ok: false, message });

  let rawIps: unknown;
  let rawCnames: unknown;

  if (Array.isArray(raw)) {
    rawIps = raw;
    rawCnames = [];
  } else if (typeof raw === 'object' && raw !== null) {
    const obj = raw as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (key !== 'ips' && key !== 'cnames') {
        return bad(`Unknown resolution key ${show(key)}`);
      }
    }
    rawIps = obj.ips === undefined ? [] : obj.ips;
    rawCnames = obj.cnames === undefined ? [] : obj.cnames;
  } else {
    return bad('Resolution must be an array or an object');
  }

  if (!Array.isArray(rawIps) || !Array.isArray(rawCnames)) {
    return bad('Resolution ips and cnames must be arrays');
  }
  if (rawIps.length > MAX_RESOLVED_IPS || rawCnames.length > MAX_CNAMES) {
    return bad(
      `Resolution exceeds ${MAX_RESOLVED_IPS} IPs or ${MAX_CNAMES} CNAMEs`,
    );
  }

  const ips: HostRef[] = [];
  for (const entry of rawIps as unknown[]) {
    if (typeof entry !== 'string') return bad('Resolved IPs must be strings');
    const ip = parseIp(entry);
    if (ip === null) return bad(`Invalid resolved IP ${show(entry)}`);
    ips.push(
      Object.freeze({ kind: 'ip' as const, version: ip.version, value: ip.value }),
    );
  }

  const cnames: string[] = [];
  for (const entry of rawCnames as unknown[]) {
    if (typeof entry !== 'string') return bad('CNAMEs must be strings');
    const norm = normalizeDomain(entry);
    if (!norm.ok) return bad(`Invalid CNAME ${show(entry)}`);
    cnames.push(norm.value);
  }

  return {
    ok: true,
    resolution: Object.freeze({
      ips: Object.freeze(ips) as Resolution['ips'],
      cnames: Object.freeze(cnames),
    }),
  };
}

/**
 * Turns raw strings into a normalized Target and optional Resolution.
 * Never throws; every failure is INVALID_TARGET with a bounded, escaped message.
 *
 * - Accepts http(s) URLs, domains, IPv4, IPv6 (bare or bracketed), with optional ports.
 * - Rejects userinfo, query, fragment, wildcards, CIDRs, and bare paths.
 * - Resolution is bounded (64 IPs, 16 CNAMEs) and normalized the same way as targets.
 * - The result is frozen, and is the only supported way to build a Target.
 */
export function parseTarget(
  rawTarget: unknown,
  rawResolution?: unknown,
): ParseTargetResult {
  if (typeof rawTarget !== 'string') return fail('Target must be a string');
  if (rawTarget.length === 0 || rawTarget.length > MAX_TARGET_LENGTH) {
    return fail('Target is empty or too long');
  }

  const parsed = URL_SCHEME.test(rawTarget)
    ? parseUrlTarget(rawTarget)
    : parsePlainTarget(rawTarget);
  if (typeof parsed === 'string') return fail(parsed);

  if (rawResolution === undefined) return { ok: true, target: parsed };

  const res = parseResolution(rawResolution);
  if (!res.ok) return fail(res.message);
  return { ok: true, target: parsed, resolution: res.resolution };
}