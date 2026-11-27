import { formatIpv4, formatIpv6 } from './ip';
import type { HostRef } from './target';

/**
 * Canonical text for a normalized host: the name itself, dotted IPv4, or
 * compressed lowercase IPv6 without brackets. Use it when a Target must be
 * shown or logged, so one address always has one spelling.
 */
export function hostToString(host: HostRef): string {
  if (host.kind === 'name') return host.name;
  return host.version === 4 ? formatIpv4(host.value) : formatIpv6(host.value);
}