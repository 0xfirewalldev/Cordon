import {
  Actor,
  type AuditEvent,
  type AuditLog,
  type AuditRecord,
} from '@scope-guard/audit';
import {
  evaluate,
  hostToString,
  parseTarget,
  ToolClass,
  type CompiledScope,
  type Decision,
  type Resolution,
  type Target,
} from '@scope-guard/scope';
import { z } from 'zod';
import type { ScopeApprovals } from './approvals';

/**
 * Looks up DNS for a NORMALIZED hostname. Return `{ ips, cnames }` (or an array
 * of IP strings); the gate normalizes and bounds it. Never called for raw input,
 * for IP targets, or for passive tools. A throw or a timeout counts as "no
 * resolution", which denies every active tool.
 */
export interface Resolver {
  resolve(host: string): Promise<unknown>;
}

export type GateDeps = {
  readonly audit: Pick<AuditLog, 'append'>;
  readonly approvals: ScopeApprovals;
  readonly resolver?: Resolver;
  /** Injected clock, epoch milliseconds. Defaults to Date.now. */
  readonly now?: () => number;
  /** How long to wait for the resolver. Defaults to 5000. */
  readonly resolveTimeoutMs?: number;
};

const GateRequest = z
  .object({
    engagementId: z.string().min(1).max(255),
    actor: Actor,
    toolClass: ToolClass,
    target: z.string().min(1).max(2048),
  })
  .strict();
export type GateRequest = z.infer<typeof GateRequest>;

export type GateResult =
  | {
      readonly allowed: true;
      readonly decision: Decision;
      /** The decision's audit record. It exists before any action is taken. */
      readonly record: AuditRecord;
      /** The normalized target. Act on this, never on the raw input. */
      readonly target: Target;
      /**
       * Pin the connection to these addresses and nothing else. For a name
       * target they are the resolved IPs (use the name only for SNI / Host);
       * for an IP target, that IP; for a passive tool with no lookup, empty.
       */
      readonly ips: readonly string[];
    }
  | {
      readonly allowed: false;
      /** Why. Scope reason codes, or one of the gate's own (see GateDenial). */
      readonly reasons: readonly string[];
      readonly decision?: Decision;
      readonly record?: AuditRecord;
      /** False when the denial itself could not be written to the audit log. Alert on it. */
      readonly audited: boolean;
    };

/** Reasons only the gate produces. Scope's reason codes come through unchanged. */
export type GateDenial =
  | 'INVALID_REQUEST'
  | 'INVALID_TARGET'
  | 'INVALID_RESOLUTION'
  | 'SCOPE_ENGAGEMENT_MISMATCH'
  | 'SCOPE_NOT_APPROVED'
  | 'SCOPE_NOT_CURRENT'
  | 'APPROVAL_CHECK_FAILED'
  | 'AUDIT_UNAVAILABLE'
  | 'GATE_ERROR';

export interface Gate {
  check(scope: CompiledScope, request: unknown): Promise<GateResult>;
}

/** Stands in for the host of a target that could not be parsed. Raw input is never logged. */
export const INVALID_TARGET_HOST = '(invalid-target)';

const DEFAULT_RESOLVE_TIMEOUT_MS = 5000;

const denied = (
  reasons: readonly string[],
  audited: boolean,
  extra: { decision?: Decision; record?: AuditRecord } = {}
): GateResult => ({ allowed: false, reasons, audited, ...extra });

function auditTarget(target: Target | null) {
  if (target === null) return { host: INVALID_TARGET_HOST };
  return {
    host: hostToString(target.host),
    ...(target.port !== undefined ? { port: target.port } : {}),
    ...(target.protocol !== undefined ? { protocol: target.protocol } : {}),
    ...(target.url !== undefined ? { urlPath: target.url.path } : {}),
  };
}

/**
 * The single place that decides whether an action may happen.
 *
 * Fail-closed by construction: `allowed: true` is returned only after
 *   1. the request is well formed,
 *   2. the scope belongs to the engagement and is its latest approved version,
 *   3. the target (and every resolved hop) passes `evaluate`, and
 *   4. the decision was written to the audit log.
 * Anything else, including any exception, is a denial. This function never throws.
 *
 * A caller that gets `allowed: false` must not perform the action. Call `check`
 * again for every URL a tool actually requests: a host decision does not cover
 * path-level rules.
 */
export function createGate(deps: GateDeps): Gate {
  const { audit, approvals, resolver, now = Date.now } = deps;
  const resolveTimeoutMs = deps.resolveTimeoutMs ?? DEFAULT_RESOLVE_TIMEOUT_MS;
  if (!Number.isInteger(resolveTimeoutMs) || resolveTimeoutMs <= 0) {
    throw new RangeError('resolveTimeoutMs must be a positive integer');
  }

  async function resolveHost(host: string): Promise<unknown> {
    if (resolver === undefined) return undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        resolver.resolve(host),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('timeout')),
            resolveTimeoutMs
          );
        }),
      ]);
    } catch {
      return undefined;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  async function record(
    request: GateRequest,
    scope: CompiledScope,
    evaluatedAt: number,
    target: Target | null,
    resolution: Resolution | undefined,
    outcome: {
      allowed: boolean;
      reasons: readonly string[];
      matchedRuleIds: readonly string[];
    }
  ) {
    const event: AuditEvent = {
      engagementId: request.engagementId,
      actor: request.actor,
      type: 'decision',
      payload: {
        target: auditTarget(target),
        toolClass: request.toolClass,
        allowed: outcome.allowed,
        reasons: [...outcome.reasons],
        matchedRuleIds: [...outcome.matchedRuleIds],
        scopeVersionHash: scope.hash,
        evaluatedAt,
        ...(resolution !== undefined
          ? {
              resolution: {
                ips: resolution.ips.map(hostToString),
                cnames: [...resolution.cnames],
              },
            }
          : {}),
      },
    };
    return audit.append(event);
  }

  async function run(
    scope: CompiledScope,
    rawRequest: unknown
  ): Promise<GateResult> {
    const parsedRequest = GateRequest.safeParse(rawRequest);
    if (!parsedRequest.success) return denied(['INVALID_REQUEST'], false);
    const request = parsedRequest.data;

    const t = now();
    const evaluatedAt = Number.isSafeInteger(t) && t >= 0 ? t : 0;

    // 1. Things that make evaluation meaningless. All are checked, so the audit
    //    record lists every problem, not just the first.
    const first = parseTarget(request.target);
    const preReasons: string[] = [];
    if (!first.ok) preReasons.push('INVALID_TARGET');

    if (scope.engagementId !== request.engagementId) {
      preReasons.push('SCOPE_ENGAGEMENT_MISMATCH');
    } else {
      try {
        const latest = await approvals.latestApprovedHash(request.engagementId);
        if (latest === null) preReasons.push('SCOPE_NOT_APPROVED');
        else if (latest !== scope.hash) preReasons.push('SCOPE_NOT_CURRENT');
      } catch {
        preReasons.push('APPROVAL_CHECK_FAILED');
      }
    }

    const denyBeforeEvaluation = async (
      reasons: readonly string[],
      target: Target | null
    ) => {
      const appended = await record(
        request,
        scope,
        evaluatedAt,
        target,
        undefined,
        {
          allowed: false,
          reasons,
          matchedRuleIds: [],
        }
      );
      return appended.ok
        ? denied(reasons, true, { record: appended.record })
        : denied(reasons, false);
    };

    if (preReasons.length > 0 || !first.ok) {
      return denyBeforeEvaluation(preReasons, first.ok ? first.target : null);
    }

    // 2. Resolve (active tools, name targets only) and evaluate.
    let target = first.target;
    let resolution: Resolution | undefined;

    if (
      target.host.kind === 'name' &&
      request.toolClass !== 'passive' &&
      resolver !== undefined
    ) {
      const raw = await resolveHost(hostToString(target.host));
      if (raw !== undefined) {
        const second = parseTarget(request.target, raw);
        if (!second.ok)
          return denyBeforeEvaluation(['INVALID_RESOLUTION'], target);
        target = second.target;
        resolution = second.resolution;
      }
    }

    const decision = evaluate(
      scope,
      target,
      { now: t, toolClass: request.toolClass },
      resolution
    );

    // 3. Write the decision down BEFORE anything may act on it.
    const appended = await record(
      request,
      scope,
      evaluatedAt,
      target,
      resolution,
      decision
    );
    if (!appended.ok) {
      return decision.allowed
        ? denied(['AUDIT_UNAVAILABLE'], false)
        : denied(decision.reasons, false, { decision });
    }

    if (!decision.allowed) {
      return denied(decision.reasons, true, {
        decision,
        record: appended.record,
      });
    }

    const ips =
      resolution !== undefined
        ? resolution.ips.map(hostToString)
        : target.host.kind === 'ip'
          ? [hostToString(target.host)]
          : [];

    return { allowed: true, decision, record: appended.record, target, ips };
  }

  return {
    async check(scope, request) {
      try {
        return await run(scope, request);
      } catch {
        return denied(['GATE_ERROR'], false);
      }
    },
  };
}
