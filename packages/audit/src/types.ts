import { z } from 'zod';
import {
  AuthFailurePayload,
  DecisionPayload,
  EngagementStatusChangedPayload,
  RunFinishedPayload,
  RunStartedPayload,
  ScopeVersionApprovedPayload,
  ScopeVersionCreatedPayload,
} from './events';
import { EpochMs, Id, Sha256Hash } from './primitives';

/**
 * Who did it. A person, a worker and the platform itself are different things
 * when someone asks who approved a scope change, so the kind is recorded.
 */
export const Actor = z
  .object({
    kind: z.enum(['user', 'service', 'system']),
    id: Id,
  })
  .strict();
export type Actor = z.infer<typeof Actor>;

/** Supplied by the caller. */
const eventFields = {
  engagementId: Id,
  actor: Actor,
};

/**
 * Assigned by the log, never by the caller:
 * - seq starts at 0 (the genesis record)
 * - timestamp comes from the log's injected clock, so an actor can't backdate an event
 * - prevHash and hash are computed by chain.ts
 */
const assignedFields = {
  seq: z.number().int().nonnegative(),
  timestamp: EpochMs,
  prevHash: Sha256Hash,
  hash: Sha256Hash,
};

/**
 * Builds the event and record schemas for one event type from the same pieces,
 * so the two can't drift. Each is a single strict object: an intersection of
 * two strict objects would reject every input.
 */
function variant<T extends string, P extends z.ZodType>(
  type: T,
  payload: P,
) {
  const fields = { type: z.literal(type), payload };
  return {
    event: z.object({ ...eventFields, ...fields }).strict(),
    record: z.object({ ...eventFields, ...assignedFields, ...fields }).strict(),
  };
}

const decision = variant('decision', DecisionPayload);
const scopeVersionCreated = variant(
  'scope_version_created',
  ScopeVersionCreatedPayload,
);
const scopeVersionApproved = variant(
  'scope_version_approved',
  ScopeVersionApprovedPayload,
);
const engagementStatusChanged = variant(
  'engagement_status_changed',
  EngagementStatusChangedPayload,
);
const runStarted = variant('run_started', RunStartedPayload);
const runFinished = variant('run_finished', RunFinishedPayload);
const authFailure = variant('auth_failure', AuthFailurePayload);

/** What a caller hands to the log. Carries no seq, timestamp or hashes. */
export const AuditEvent = z.discriminatedUnion('type', [
  decision.event,
  scopeVersionCreated.event,
  scopeVersionApproved.event,
  engagementStatusChanged.event,
  runStarted.event,
  runFinished.event,
  authFailure.event,
]);
export type AuditEvent = z.infer<typeof AuditEvent>;
export type AuditEventType = AuditEvent['type'];

/**
 * What the log stores: the event plus the assigned fields. This only checks
 * shape. Whether `hash` is correct and `prevHash` links to the previous
 * record is chain.ts's job.
 */
export const AuditRecord = z.discriminatedUnion('type', [
  decision.record,
  scopeVersionCreated.record,
  scopeVersionApproved.record,
  engagementStatusChanged.record,
  runStarted.record,
  runFinished.record,
  authFailure.record,
]);
export type AuditRecord = z.infer<typeof AuditRecord>;