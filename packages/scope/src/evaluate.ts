import type { CompiledRule, CompiledScope } from './compile';
import { evaluateExclude, evaluateInclude } from './match';
import type { ConstraintReason } from './match';
import type {
  EvalContext,
  HostRef,
  MatchContext,
  Resolution,
  Target,
} from './target';
import type { Decision, ReasonCode } from './types';

/**
 * Fail-closed evaluation. Every denial carries a specific reason; there is no
 * catch-all. Order of checks:
 *
 * 1. Window: notBefore <= now < notAfter. A missing or invalid `now` is outside the window.
 * 2. The target itself: any matching exclude denies (EXCLUDED), then at least one
 *    include must allow it. A covering include whose ports/protocols/toolClasses fail
 *    reports that constraint (PORT_NOT_ALLOWED, ...) instead of NO_INCLUDE_MATCH.
 * 3. Name targets: every resolved hop gets the same check, as a host-only target
 *    carrying the original effective port and protocol.
 *      - each CNAME   -> CNAME_OUT_OF_SCOPE on failure
 *      - each IP      -> RESOLVED_IP_OUT_OF_SCOPE on failure
 *    A hop IP must be covered by an ip/cidr include (a domain include is not enough)
 *    and must not be excluded, so an in-scope name that resolves into an excluded or
 *    third-party address is denied.
 *    Active tools (anything but 'passive') require at least one resolved IP
 *    (RESOLUTION_REQUIRED). Passive tools don't contact the target, so resolution is
 *    optional for them, but if it is supplied it is still checked.
 *    More than 64 IPs or 16 CNAMEs is INVALID_TARGET: truncating would skip hops.
 *    Resolution is ignored for IP targets.
 *
 * All checks run (no early exit) so the Decision lists every reason, in a fixed order:
 * target, RESOLUTION_REQUIRED / INVALID_TARGET, CNAMEs, IPs.
 *
 * matchedRuleIds: on allow, the include rules that allowed the target and each hop;
 * on deny, the rules responsible (excludes, or covering includes whose constraint failed).
 *
 * The Target and Resolution must come from the normalizers, never from raw input.
 */

const MAX_RESOLVED_IPS = 64;
const MAX_CNAMES = 16;

type Verdict =
  | { readonly ok: true; readonly ruleIds: readonly string[] }
  | {
      readonly ok: false;
      readonly reason: ReasonCode;
      readonly ruleIds: readonly string[];
    };

function checkTarget(
  rules: readonly CompiledRule[],
  target: Target,
  ctx: MatchContext
): Verdict {
  const excluding: string[] = [];
  for (const rule of rules) {
    if (evaluateExclude(rule, target, ctx)) excluding.push(rule.id);
  }
  if (excluding.length > 0) {
    return { ok: false, reason: 'EXCLUDED', ruleIds: excluding };
  }

  const allowed: string[] = [];
  const constrained: { id: string; reason: ConstraintReason }[] = [];
  for (const rule of rules) {
    const result = evaluateInclude(rule, target, ctx);
    if (result.status === 'allowed') allowed.push(rule.id);
    else if (result.status === 'constrained') {
      constrained.push({ id: rule.id, reason: result.reason });
    }
  }
  if (allowed.length > 0) return { ok: true, ruleIds: allowed };

  const first = constrained[0];
  if (first !== undefined) {
    return {
      ok: false,
      reason: first.reason,
      ruleIds: constrained.map(c => c.id),
    };
  }
  return { ok: false, reason: 'NO_INCLUDE_MATCH', ruleIds: [] };
}

function effectivePort(target: Target): number | undefined {
  if (target.port !== undefined) return target.port;
  if (target.url === undefined) return undefined;
  return target.url.scheme === 'https' ? 443 : 80;
}

/** A host-only target for a resolved hop, carrying the original connection details. */
function hopTarget(host: HostRef, original: Target): Target {
  const port = effectivePort(original);
  const protocol = original.protocol ?? original.url?.scheme;
  return {
    host,
    ...(port !== undefined ? { port } : {}),
    ...(protocol !== undefined ? { protocol } : {}),
  };
}

export function evaluate(
  scope: CompiledScope,
  target: Target,
  ctx: EvalContext,
  resolution?: Resolution
): Decision {
  const validNow = Number.isSafeInteger(ctx.now) && ctx.now >= 0;
  const evaluatedAt = validNow ? ctx.now : 0;

  const deny = (
    reasons: readonly ReasonCode[],
    ruleIds: readonly string[]
  ): Decision => ({
    allowed: false,
    reasons: [...reasons],
    matchedRuleIds: [...ruleIds],
    scopeVersionHash: scope.hash,
    evaluatedAt,
  });

  if (!validNow || ctx.now < scope.notBefore || ctx.now >= scope.notAfter) {
    return deny(['OUTSIDE_WINDOW'], []);
  }

  const reasons = new Set<ReasonCode>();
  const failIds = new Set<string>();
  const allowIds = new Set<string>();

  const record = (verdict: Verdict, hopReason?: ReasonCode): void => {
    if (verdict.ok) {
      for (const id of verdict.ruleIds) allowIds.add(id);
      return;
    }
    reasons.add(hopReason ?? verdict.reason);
    for (const id of verdict.ruleIds) failIds.add(id);
  };

  record(checkTarget(scope.rules, target, ctx));

  if (target.host.kind === 'name') {
    const ips = resolution?.ips ?? [];
    const cnames = resolution?.cnames ?? [];

    if (ctx.toolClass !== 'passive' && ips.length === 0) {
      reasons.add('RESOLUTION_REQUIRED');
    }

    if (ips.length > MAX_RESOLVED_IPS || cnames.length > MAX_CNAMES) {
      reasons.add('INVALID_TARGET');
    } else {
      for (const name of cnames) {
        record(
          checkTarget(
            scope.rules,
            hopTarget({ kind: 'name', name }, target),
            ctx
          ),
          'CNAME_OUT_OF_SCOPE'
        );
      }
      for (const host of ips) {
        record(
          checkTarget(scope.rules, hopTarget(host, target), ctx),
          'RESOLVED_IP_OUT_OF_SCOPE'
        );
      }
    }
  }

  if (reasons.size > 0) return deny([...reasons], [...failIds]);

  return {
    allowed: true,
    reasons: ['INCLUDED'],
    matchedRuleIds: [...allowIds],
    scopeVersionHash: scope.hash,
    evaluatedAt,
  };
}
