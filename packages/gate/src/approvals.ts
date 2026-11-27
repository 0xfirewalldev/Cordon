import {
  GENESIS_PREV_HASH,
  verifyChain,
  type Actor,
  type AuditLog,
  type AuditRecord,
} from '@scope-guard/audit';

/**
 * Which scope version may be enforced for an engagement right now.
 *
 * Only the MOST RECENT valid approval counts, so approving a new version
 * retires the old one (no rollback to a more permissive scope by accident).
 */
export interface ScopeApprovals {
  /**
   * The `versionHash` of the most recent valid approval, or `null` if the
   * engagement has none. Throws if the answer can't be established (store
   * failure, broken chain): callers must treat a throw as "not approved".
   */
  latestApprovedHash(engagementId: string): Promise<string | null>;
}

type Created = { readonly scopeVersionId: string; readonly actor: Actor };

type State = {
  /** Where the next page starts, and what it must link to. */
  readonly nextSeq: number;
  readonly prevHash: string;
  readonly timestamp: number;
  /** The last record folded in (-1 / null when the chain is empty). */
  readonly lastSeq: number;
  readonly lastHash: string | null;
  /** First creation event per scope hash. */
  readonly created: ReadonlyMap<string, Created>;
  readonly latest: string | null;
};

const EMPTY: State = {
  nextSeq: 0,
  prevHash: GENESIS_PREV_HASH,
  timestamp: 0,
  lastSeq: -1,
  lastHash: null,
  created: new Map(),
  latest: null,
};

const PAGE_SIZE = 500;
const MAX_REFRESH_ATTEMPTS = 3;

/**
 * Two-person rule: the approver must be a person (`user`) and must not be the
 * actor that created the version.
 */
function isValidApprover(creator: Actor, approver: Actor): boolean {
  if (approver.kind !== 'user') return false;
  return !(creator.kind === approver.kind && creator.id === approver.id);
}

function fold(state: State, page: readonly AuditRecord[]): State {
  const created = new Map(state.created);
  let latest = state.latest;

  for (const record of page) {
    if (record.type === 'scope_version_created') {
      // The first creation event is the creator. A later duplicate can't
      // take the creator's place.
      if (!created.has(record.payload.versionHash)) {
        created.set(record.payload.versionHash, {
          scopeVersionId: record.payload.scopeVersionId,
          actor: record.actor,
        });
      }
    } else if (record.type === 'scope_version_approved') {
      const creation = created.get(record.payload.versionHash);
      if (
        creation !== undefined &&
        creation.scopeVersionId === record.payload.scopeVersionId &&
        isValidApprover(creation.actor, record.actor)
      ) {
        latest = record.payload.versionHash;
      }
    }
  }

  const last = page[page.length - 1]!;
  return {
    nextSeq: last.seq + 1,
    prevHash: last.hash,
    timestamp: last.timestamp,
    lastSeq: last.seq,
    lastHash: last.hash,
    created,
    latest,
  };
}

/** Reads and verifies everything after `start`, page by page. */
async function scan(
  log: Pick<AuditLog, 'list'>,
  engagementId: string,
  start: State
): Promise<State> {
  let state = start;
  for (;;) {
    let page: readonly AuditRecord[];
    try {
      page = await log.list(engagementId, {
        fromSeq: state.nextSeq,
        limit: PAGE_SIZE,
      });
    } catch {
      throw new Error('Failed to read audit records');
    }
    if (page.length === 0) return state;

    const verified = verifyChain(page, {
      engagementId,
      from: {
        seq: state.nextSeq,
        prevHash: state.prevHash,
        timestamp: state.timestamp,
      },
    });
    if (!verified.ok) throw new Error('Audit chain failed verification');

    state = fold(state, page);
  }
}

/**
 * Derives approvals from the audit chain itself, so "approved" means "a
 * `scope_version_approved` record exists, by a different person than the
 * creator, in a chain that verifies".
 *
 * Incremental: each call reads only records added since the last call, and
 * verifies them against the previous position. It then compares the chain's
 * head with what it processed, so records removed or rewritten after they were
 * read are detected for as long as the process lives. A restart re-verifies
 * from genesis. Detecting a chain rewritten while the process was down needs
 * an externally anchored head (see AuditLog.verify's `expectedHead`).
 *
 * Approvals are never retracted (there is no revocation event), so a hash that
 * stops being the latest does so only because a newer approval superseded it.
 */
export function createAuditApprovals(
  log: Pick<AuditLog, 'list' | 'head'>
): ScopeApprovals {
  const states = new Map<string, State>();

  return {
    async latestApprovedHash(engagementId: string): Promise<string | null> {
      for (let attempt = 0; attempt < MAX_REFRESH_ATTEMPTS; attempt++) {
        const next = await scan(
          log,
          engagementId,
          states.get(engagementId) ?? EMPTY
        );
        states.set(engagementId, next);

        let head: AuditRecord | null;
        try {
          head = await log.head(engagementId);
        } catch {
          throw new Error('Failed to read audit head');
        }

        const consistent =
          head === null
            ? next.lastSeq === -1
            : head.seq === next.lastSeq && head.hash === next.lastHash;
        if (consistent) return next.latest;

        // Records landed after the scan: read them and check again.
        if (head !== null && head.seq > next.lastSeq) continue;

        // The chain got shorter, or a record we already verified changed.
        states.delete(engagementId);
        throw new Error(
          'Audit chain no longer matches the history already verified'
        );
      }
      throw new Error('Audit chain kept changing during verification');
    },
  };
}
