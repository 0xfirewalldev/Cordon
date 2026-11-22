import type { CompiledRule } from './compile';
import { parseIp } from './ip';
import type { HostRef, MatchContext, Target } from './target';
import type { Protocol } from './types';

/**
 * Pure matchers. No I/O, no clock, no DNS.
 *
 * Semantics (keep in sync with the tests):
 * - domain:     exact host equality.
 * - wildcard:   subdomains only, never the apex ("*.example.com" excludes "example.com",
 *               and "evilexample.com" never matches because of the leading dot).
 * - ip / cidr:  numeric comparison, same IP version only.
 * - url_prefix: needs a URL target. Include rules require the same scheme, host, effective
 *               port and a path match on a segment boundary ("/admin" covers "/admin" and
 *               "/admin/x", not "/administrator"), case-sensitive. Exclude rules are
 *               deliberately broader and fail safe: scheme and port are ignored and the
 *               path compares case-insensitively.
 * - A url_prefix rule never matches a host-only target. The gate must re-check each URL a
 *   tool actually requests.
 * - Constraints (ports, protocols, toolClasses): absent means any. Unknown target values
 *   fail an include's constraint but do NOT stop an exclude from applying.
 */

type RuleOf<T extends CompiledRule['targetType']> = Extract<
  CompiledRule,
  { targetType: T }
>;
type IpHost = Extract<HostRef, { kind: 'ip' }>;

export type ConstraintReason =
  'PORT_NOT_ALLOWED' | 'PROTOCOL_NOT_ALLOWED' | 'TOOL_CLASS_NOT_ALLOWED';

export type IncludeResult =
  | { status: 'no_match' }
  | { status: 'allowed' }
  | { status: 'constrained'; reason: ConstraintReason };

function targetPort(target: Target): number | undefined {
  if (target.port !== undefined) return target.port;
  if (target.url !== undefined) return target.url.scheme === 'https' ? 443 : 80;
  return undefined;
}

function targetProtocol(target: Target): Protocol | undefined {
  return target.protocol ?? target.url?.scheme;
}

function cidrContains(rule: RuleOf<'cidr'>, host: IpHost): boolean {
  if (rule.version !== host.version) return false;
  const bits = rule.version === 4 ? 32 : 128;
  const shift = BigInt(bits - rule.prefix);
  return host.value >> shift === rule.network >> shift;
}

function sameHost(ruleHost: string, host: HostRef): boolean {
  if (host.kind === 'name') return host.name === ruleHost;
  const ruleIp = parseIp(ruleHost);
  return (
    ruleIp !== null &&
    ruleIp.version === host.version &&
    ruleIp.value === host.value
  );
}

function pathCovers(
  rulePath: string,
  targetPath: string,
  ignoreCase: boolean
): boolean {
  const norm = (p: string): string => {
    const s = ignoreCase ? p.toLowerCase() : p;
    return s.length > 1 && s.endsWith('/') ? s.slice(0, -1) : s;
  };
  const r = norm(rulePath);
  const t = norm(targetPath);
  if (r === '/') return true;
  return t === r || t.startsWith(`${r}/`);
}

function matchUrlPrefix(rule: RuleOf<'url_prefix'>, target: Target): boolean {
  const url = target.url;
  if (url === undefined) return false;
  if (!sameHost(rule.host, target.host)) return false;

  const strict = rule.effect === 'include';
  if (strict) {
    if (url.scheme !== rule.scheme) return false;
    if (targetPort(target) !== rule.port) return false;
  }
  return pathCovers(rule.path, url.path, !strict);
}

/** Does the rule's pattern cover the target? Ignores ports/protocols/toolClasses. */
export function matchTarget(rule: CompiledRule, target: Target): boolean {
  const host = target.host;
  switch (rule.targetType) {
    case 'domain':
      return host.kind === 'name' && host.name === rule.host;
    case 'wildcard':
      return host.kind === 'name' && host.name.endsWith(`.${rule.base}`);
    case 'ip':
      return (
        host.kind === 'ip' &&
        host.version === rule.version &&
        host.value === rule.value
      );
    case 'cidr':
      return host.kind === 'ip' && cidrContains(rule, host);
    case 'url_prefix':
      return matchUrlPrefix(rule, target);
    default: {
      // Unknown rule type: fail closed. An unknown exclude applies, an unknown include doesn't.
      const unreachable: never = rule;
      const effect = (unreachable as CompiledRule).effect;
      return effect === 'exclude';
    }
  }
}

/** Strict: a constraint the target can't satisfy, or whose value is unknown, fails. */
function failedConstraint(
  rule: CompiledRule,
  target: Target,
  ctx: MatchContext
): ConstraintReason | null {
  if (rule.ports !== undefined) {
    const port = targetPort(target);
    if (port === undefined || !rule.ports.includes(port))
      return 'PORT_NOT_ALLOWED';
  }
  if (rule.protocols !== undefined) {
    const protocol = targetProtocol(target);
    if (protocol === undefined || !rule.protocols.includes(protocol)) {
      return 'PROTOCOL_NOT_ALLOWED';
    }
  }
  if (
    rule.toolClasses !== undefined &&
    !rule.toolClasses.includes(ctx.toolClass)
  ) {
    return 'TOOL_CLASS_NOT_ALLOWED';
  }
  return null;
}

/** Lenient: an exclude's constraint only releases the target when the value is known and outside it. */
function excludeConstraintsApply(
  rule: CompiledRule,
  target: Target,
  ctx: MatchContext
): boolean {
  if (rule.ports !== undefined) {
    const port = targetPort(target);
    if (port !== undefined && !rule.ports.includes(port)) return false;
  }
  if (rule.protocols !== undefined) {
    const protocol = targetProtocol(target);
    if (protocol !== undefined && !rule.protocols.includes(protocol))
      return false;
  }
  if (
    rule.toolClasses !== undefined &&
    !rule.toolClasses.includes(ctx.toolClass)
  ) {
    return false;
  }
  return true;
}

/**
 * Evaluates one include rule.
 * - no_match:    the pattern doesn't cover the target (or the rule isn't an include).
 * - constrained: the pattern covers it but a constraint fails, so the caller can report
 *                PORT_NOT_ALLOWED / PROTOCOL_NOT_ALLOWED / TOOL_CLASS_NOT_ALLOWED.
 * - allowed:     covered and every constraint holds.
 */
export function evaluateInclude(
  rule: CompiledRule,
  target: Target,
  ctx: MatchContext
): IncludeResult {
  if (rule.effect !== 'include' || !matchTarget(rule, target)) {
    return { status: 'no_match' };
  }
  const reason = failedConstraint(rule, target, ctx);
  return reason === null
    ? { status: 'allowed' }
    : { status: 'constrained', reason };
}

/** True when an exclude rule applies to the target. */
export function evaluateExclude(
  rule: CompiledRule,
  target: Target,
  ctx: MatchContext
): boolean {
  return (
    rule.effect === 'exclude' &&
    matchTarget(rule, target) &&
    excludeConstraintsApply(rule, target, ctx)
  );
}
