import {
  createAuditLog,
  type Actor,
  type AuditEvent,
  type AuditLog,
  type AuditRecord,
} from '@scope-guard/audit';
import type { AuditStore, ListOptions } from '@scope-guard/audit';
import { createMemoryStore } from '@scope-guard/audit/testing';
import {
  compileScope,
  computeScopeHash,
  type CompiledScope,
  type RawRule,
} from '@scope-guard/scope';

export const ENG = 'eng-1';
export const NOW = Date.UTC(2026, 5, 1);
export const ALICE: Actor = { kind: 'user', id: 'alice' };
export const BOB: Actor = { kind: 'user', id: 'bob' };
export const WORKER: Actor = { kind: 'service', id: 'worker-1' };

export const BASE_RULES: Omit<RawRule, 'id'>[] = [
  { targetType: 'domain', effect: 'include', pattern: 'example.com' }, // r1
  { targetType: 'wildcard', effect: 'include', pattern: '*.example.com' }, // r2
  { targetType: 'cidr', effect: 'include', pattern: '198.51.100.0/24' }, // r3
  { targetType: 'ip', effect: 'exclude', pattern: '198.51.100.66' }, // r4
  {
    targetType: 'url_prefix',
    effect: 'exclude',
    pattern: 'https://example.com/admin',
  }, // r5
];

let scopeCounter = 0;
export function makeScope(
  rules: Omit<RawRule, 'id'>[] = BASE_RULES,
  engagementId = ENG
): CompiledScope {
  const draft = {
    id: `sv-${++scopeCounter}`,
    engagementId,
    rules: rules.map((r, i) => ({ id: `r${i + 1}`, ...r })),
    notBefore: Date.UTC(2026, 0, 1),
    notAfter: Date.UTC(2026, 11, 31),
    createdAt: Date.UTC(2026, 0, 1),
  };
  const result = compileScope({ ...draft, hash: computeScopeHash(draft) });
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.scope;
}

/** A second, different scope for the same engagement. */
export const widerScope = () =>
  makeScope([
    ...BASE_RULES,
    { targetType: 'domain', effect: 'include', pattern: 'extra.example.org' },
  ]);

export function newLog(store: AuditStore = createMemoryStore()): AuditLog {
  let tick = 1000;
  return createAuditLog({ store, now: () => (tick += 1) });
}

export const createdEvent = (
  scope: CompiledScope,
  actor: Actor
): AuditEvent => ({
  engagementId: scope.engagementId,
  actor,
  type: 'scope_version_created',
  payload: {
    scopeVersionId: scope.id,
    versionHash: scope.hash,
    ruleCount: scope.rules.length,
    notBefore: scope.notBefore,
    notAfter: scope.notAfter,
  },
});

export const approvedEvent = (
  scope: CompiledScope,
  actor: Actor
): AuditEvent => ({
  engagementId: scope.engagementId,
  actor,
  type: 'scope_version_approved',
  payload: { scopeVersionId: scope.id, versionHash: scope.hash },
});

export async function mustAppend(
  log: Pick<AuditLog, 'append'>,
  event: AuditEvent
): Promise<AuditRecord> {
  const result = await log.append(event);
  if (!result.ok) throw new Error(`append failed: ${result.code}`);
  return result.record;
}

/** Alice creates the version, Bob approves it: a valid two-person approval. */
export async function approve(
  log: Pick<AuditLog, 'append'>,
  scope: CompiledScope
) {
  await mustAppend(log, createdEvent(scope, ALICE));
  await mustAppend(log, approvedEvent(scope, BOB));
}

/** A store backed by a plain array, so tests can truncate or rewrite history. */
export function arrayStore() {
  const records: AuditRecord[] = [];
  const listCalls: (number | undefined)[] = [];
  const store: AuditStore = {
    async head(id) {
      const m = records.filter(r => r.engagementId === id);
      return m[m.length - 1] ?? null;
    },
    async append(r) {
      records.push(r);
    },
    async list(id, opts: ListOptions = {}) {
      listCalls.push(opts.fromSeq);
      const m = records.filter(r => r.engagementId === id);
      const from = opts.fromSeq ?? 0;
      return m.slice(
        from,
        opts.limit !== undefined ? from + opts.limit : undefined
      );
    },
  };
  return { store, records, listCalls };
}
