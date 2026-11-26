import type { AuditRecord } from './types';

export const REDACTED_VALUE = '[REDACTED]';

export type RedactedRecord = AuditRecord & { readonly redacted: true };

export type RedactOptions = {
  /** Redact `actor.id`. Defaults to `true`. */
  readonly actors?: boolean;
  /** Redact `auth_failure.payload.sourceIp`. Defaults to `true`. */
  readonly sourceIps?: boolean;
  /** Redact `target.host`, `target.urlPath`, and `resolution` IPs/CNAMEs. Defaults to `false`. */
  readonly targets?: boolean;
  /** Redact free-text `engagement_status_changed.payload.reason`. Defaults to `false`. */
  readonly reasons?: boolean;
};

function redactTarget<
  T extends {
    host: string;
    port?: number;
    protocol?: string;
    urlPath?: string;
  },
>(target: T): T {
  return {
    ...target,
    host: REDACTED_VALUE,
    ...(target.urlPath !== undefined ? { urlPath: REDACTED_VALUE } : {}),
  };
}

/**
 * Returns a redacted deep copy of an `AuditRecord` marked with `redacted: true`.
 * Does not mutate the original record.
 *
 * Redacted output is strictly for display: `AuditRecord` (and therefore
 * `AuditStore.append` and `verifyChain`) rejects it at runtime. Auditors must
 * always verify the unredacted chain.
 */
export function redactRecord(
  record: AuditRecord,
  options: RedactOptions = {},
): RedactedRecord {
  const {
    actors = true,
    sourceIps = true,
    targets = false,
    reasons = false,
  } = options;

  const cloned = structuredClone(record);

  if (actors) {
    cloned.actor.id = REDACTED_VALUE;
  }

  switch (cloned.type) {
    case 'decision':
      if (targets) {
        cloned.payload.target = redactTarget(cloned.payload.target);
        if (cloned.payload.resolution !== undefined) {
          cloned.payload.resolution = {
            ips: cloned.payload.resolution.ips.map(() => REDACTED_VALUE),
            cnames: cloned.payload.resolution.cnames.map(() => REDACTED_VALUE),
          };
        }
      }
      break;

    case 'run_started':
      if (targets) {
        cloned.payload.target = redactTarget(cloned.payload.target);
      }
      break;

    case 'auth_failure':
      if (sourceIps && cloned.payload.sourceIp !== undefined) {
        cloned.payload.sourceIp = REDACTED_VALUE;
      }
      break;

    case 'engagement_status_changed':
      if (reasons && cloned.payload.reason !== undefined) {
        cloned.payload.reason = REDACTED_VALUE;
      }
      break;

    case 'scope_version_created':
    case 'scope_version_approved':
    case 'run_finished':
      break;

    default: {
      const unreachable: never = cloned;
      void unreachable;
      break;
    }
  }

  return { ...cloned, redacted: true };
}

/**
 * Redacts an array of audit records for display without mutating the input.
 */
export function redactRecords(
  records: readonly AuditRecord[],
  options: RedactOptions = {},
): RedactedRecord[] {
  return records.map((record) => redactRecord(record, options));
}
