import type { ReasonCode } from './types';

export type NormalizeResult =
  | { ok: true; value: string }
  | { ok: false; reason: ReasonCode };

const ok = (value: string): NormalizeResult => ({ ok: true, value });
const invalid = (): NormalizeResult => ({
  ok: false,
  reason: 'INVALID_TARGET',
});

const MAX_RAW_LENGTH = 1024;
const MAX_HOSTNAME_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;

// Raw input allowlist: letters, marks and numbers from any script, plus '.' and '-'.
// Everything else is rejected before parsing: whitespace, control and format
// characters (zero-width, bidi), '_', '*', '/', '@', ':', '?', '#', '\', '%',
// brackets, and look-alike dots such as U+3002. Underscore is excluded on purpose,
// so names like _dmarc are never valid targets. Revisit if recon needs SRV/DKIM names.
const RAW_ALLOWED = /^[\p{L}\p{M}\p{N}.-]+$/u;

// Final (post-IDNA) label: lowercase LDH, no leading/trailing hyphen.
const LDH_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

// Last label that WHATWG URL / inet_aton would treat as a number (decimal or hex).
const NUMERIC_LABEL = /^(?:\d+|0x[0-9a-f]*)$/i;

/**
 * Validates an already-converted ASCII hostname: total and per-label length,
 * lowercase LDH labels, no empty labels, and not IP-shaped.
 * Run this on the OUTPUT of conversion, never only on raw input.
 */
export function isValidAsciiHostname(host: string): boolean {
  if (host.length === 0 || host.length > MAX_HOSTNAME_LENGTH) return false;
  const labels = host.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LENGTH) return false;
    if (!LDH_LABEL.test(label)) return false;
  }
  return !NUMERIC_LABEL.test(labels.at(-1) ?? '');
}

/**
 * Normalizes a domain to its canonical ASCII (punycode, lowercase) form.
 * Never throws. Anything that fails returns INVALID_TARGET.
 *
 * Downstream code (scope check, audit log, tool invocation) must use the
 * returned value only, never the raw input.
 */
export function normalizeDomain(rawInput: unknown): NormalizeResult {
  if (typeof rawInput !== 'string') return invalid();
  if (rawInput.length === 0 || rawInput.length > MAX_RAW_LENGTH) return invalid();
  if (!RAW_ALLOWED.test(rawInput)) return invalid();

  let hostname: string;
  try {
    // WHATWG URL does the IDNA/punycode conversion and lowercasing.
    hostname = new URL(`http://${rawInput}`).hostname;
  } catch {
    return invalid();
  }

  // Strip at most one trailing dot (FQDN form). A second one leaves an empty label.
  const host = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;

  return isValidAsciiHostname(host) ? ok(host) : invalid();
}

/**
 * Normalizes a wildcard pattern like "*.example.com".
 * Returns the normalized BASE domain ("example.com"), without the "*.".
 * Matches subdomains only, never the apex. Single-label bases ("*.com")
 * are rejected so one rule can't put an entire TLD in scope.
 */
export function normalizeWildcard(rawInput: unknown): NormalizeResult {
  if (typeof rawInput !== 'string' || !rawInput.startsWith('*.')) {
    return invalid();
  }
  const base = normalizeDomain(rawInput.slice(2));
  if (!base.ok) return base;
  if (!base.value.includes('.')) return invalid();
  return base;
}