import { z } from 'zod';
import { EpochMs, Id, Sha256Hash } from './primitives';

/**
 * One strict payload schema per event type. The pairing of `type` and payload
 * happens in types.ts. Payloads are hashed, so they hold only JSON-safe values:
 * strings, integers, booleans and bounded arrays. Never bigint, Date or undefined.
 *
 * Who did it (`actor`) and when it was recorded (`timestamp`) belong to the record,
 * and the log assigns the time. Payloads must not repeat them, or a payload could
 * carry a backdated time next to an honest record time. The one exception is
 * DecisionPayload.evaluatedAt, which is the `now` the engine evaluated against.
 *
 * audit deliberately does not import from @scope-guard/scope. Callers convert a
 * Decision and its Target into this shape, so audit stays small and independent.
 */

// Same values as scope's ToolClass. Duplicated on purpose; keep in sync.
const ToolClass = z.enum(['passive', 'active-light', 'active-intrusive']);

/** The normalized target as text. IPv6 hosts are unbracketed; IPv4-mapped IPv6 is already IPv4. */
const AuditTarget = z
  .object({
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65535).optional(),
    protocol: z.string().min(1).max(16).optional(),
    urlPath: z.string().min(1).max(2048).optional(),
  })
  .strict();

/** What DNS returned, as normalized strings. Bounds match the engine (64 IPs, 16 CNAMEs). */
const AuditResolution = z
  .object({
    ips: z.array(z.string().min(1).max(45)).max(64),
    cnames: z.array(z.string().min(1).max(253)).max(16),
  })
  .strict();

/** type: 'decision' */
export const DecisionPayload = z
  .object({
    target: AuditTarget,
    toolClass: ToolClass,
    allowed: z.boolean(),
    // Plain bounded strings, not an enum: if scope adds a reason code, the
    // log must not start rejecting events.
    reasons: z.array(z.string().min(1).max(64)).min(1).max(16),
    // Oversized lists are rejected, not truncated: a silently shortened list
    // would misreport which rules decided.
    matchedRuleIds: z.array(Id).max(1000),
    scopeVersionHash: Sha256Hash,
    evaluatedAt: EpochMs,
    resolution: AuditResolution.optional(),
  })
  .strict();
export type DecisionPayload = z.infer<typeof DecisionPayload>;

/** type: 'scope_version_created'. The creator is the record's actor. */
export const ScopeVersionCreatedPayload = z
  .object({
    scopeVersionId: Id,
    versionHash: Sha256Hash,
    // Matches the 10,000 rule cap on scope's ScopeVersion.
    ruleCount: z.number().int().min(0).max(10_000),
    // The engagement window this version enforces, so a reviewer can see it
    // without loading the version.
    notBefore: EpochMs,
    notAfter: EpochMs,
  })
  .strict()
  .refine((p) => p.notBefore < p.notAfter, {
    message: 'notAfter must be after notBefore',
    path: ['notAfter'],
  });
export type ScopeVersionCreatedPayload = z.infer<
  typeof ScopeVersionCreatedPayload
>;

/**
 * type: 'scope_version_approved'. The approver is the record's actor.
 * Two-person approval (approver differs from the creator) is enforced by the
 * caller comparing actors; it is not expressible in a single payload.
 */
export const ScopeVersionApprovedPayload = z
  .object({
    scopeVersionId: Id,
    versionHash: Sha256Hash,
  })
  .strict();
export type ScopeVersionApprovedPayload = z.infer<
  typeof ScopeVersionApprovedPayload
>;

const EngagementStatus = z.enum(['draft', 'active', 'paused', 'closed']);

/** type: 'engagement_status_changed'. The person changing it is the record's actor. */
export const EngagementStatusChangedPayload = z
  .object({
    from: EngagementStatus,
    to: EngagementStatus,
    reason: z.string().min(1).max(500).optional(),
  })
  .strict()
  .refine((p) => p.from !== p.to, {
    message: 'from and to must differ',
    path: ['to'],
  });
export type EngagementStatusChangedPayload = z.infer<
  typeof EngagementStatusChangedPayload
>;

/** type: 'run_started' */
export const RunStartedPayload = z
  .object({
    runId: Id,
    tool: Id,
    target: AuditTarget,
    toolClass: ToolClass,
    scopeVersionHash: Sha256Hash,
  })
  .strict();
export type RunStartedPayload = z.infer<typeof RunStartedPayload>;

/** type: 'run_finished'. Duration is the difference between the two records' timestamps. */
export const RunFinishedPayload = z
  .object({
    runId: Id,
    status: z.enum(['succeeded', 'failed', 'cancelled', 'timed_out']),
    exitCode: z.number().int().min(-255).max(255).optional(),
  })
  .strict();
export type RunFinishedPayload = z.infer<typeof RunFinishedPayload>;

/**
 * type: 'auth_failure'. Only for failed access attempts against a known
 * engagement, since every record belongs to an engagement chain. Failures
 * before any engagement is known belong in a separate system log.
 * Codes only: never log tokens, passwords or free-text error messages.
 */
export const AuthFailurePayload = z
  .object({
    reason: z.enum(['invalid_token', 'expired_session', 'forbidden']),
    sourceIp: z.string().min(1).max(45).optional(),
  })
  .strict();
export type AuthFailurePayload = z.infer<typeof AuthFailurePayload>;