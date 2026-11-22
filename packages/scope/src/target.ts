import type { Protocol, ToolClass } from './types';
export type { Protocol, ToolClass };

export type IpHost = {
  readonly kind: 'ip';
  readonly version: 4 | 6;
  readonly value: bigint;
};

/** A normalized host: a DNS name or a parsed IP (mapped IPv6 already collapsed to IPv4). */
export type HostRef = { readonly kind: 'name'; readonly name: string } | IpHost;

/**
 * A normalized thing the platform wants to touch. Build it with parseTarget,
 * never by hand from raw input.
 * - `url` is present when the target is a specific URL (needed for url_prefix rules).
 * - `port` / `protocol` are explicit values; for URL targets the effective
 *   port and protocol are derived from the scheme when absent.
 */
export type Target = {
  readonly host: HostRef;
  readonly port?: number;
  readonly protocol?: Protocol;
  readonly url?: {
    readonly scheme: 'http' | 'https';
    readonly path: string;
  };
};

/**
 * What DNS returned for a hostname target, supplied by the caller (the gate).
 * `cnames` are normalized names in the CNAME chain; `ips` are the final addresses.
 */
export type Resolution = {
  readonly ips: readonly IpHost[];
  readonly cnames: readonly string[];
};

/** What the matchers need from the caller. */
export type MatchContext = {
  readonly toolClass: ToolClass;
};

/** `now` is epoch milliseconds, supplied by the caller. The engine never reads the clock. */
export type EvalContext = MatchContext & { readonly now: number };