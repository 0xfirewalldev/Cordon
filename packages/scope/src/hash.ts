import { canonicalJson, sha256Hex } from '@scope-guard/canonical';
import type { ScopeVersion } from './types';

/**
 * Prefix of every hashed string. If the serialization or the set of hashed
 * fields ever changes, bump the version, so a scope can never verify under
 * two different formats.
 */
const FORMAT_TAG = 'scope-guard.scope.v1\n';

/** A scope version's content, with or without the fields the hash leaves out. */
export type HashableScope = Omit<ScopeVersion, 'id' | 'createdAt' | 'hash'> &
  Partial<Pick<ScopeVersion, 'id' | 'createdAt' | 'hash'>>;

/**
 * SHA-256 over the format tag plus the canonical JSON of the scope's CONTENT:
 * everything except `id`, `createdAt` and `hash`. Excluding by name (not
 * allowlisting) means a field added to ScopeVersion later is covered
 * automatically instead of silently becoming editable.
 *
 * - Two versions with the same content hash the same, whatever their id or
 *   creation time.
 * - `engagementId` is covered, so an approval for one engagement's scope can't
 *   be reused for another's.
 * - Rules are hashed as written (raw patterns, notes included) and IN ORDER, so
 *   the hash identifies exactly what a human approved. Reordering or rewording
 *   a rule makes a new hash.
 *
 * This is an integrity check, not authentication: anyone who can write a
 * version can also compute its hash. That a specific hash was APPROVED has to
 * come from the approval record (the `scope_version_approved` audit event).
 *
 * Throws CanonicalError if the input can't be serialized unambiguously. Data
 * that passed the ScopeVersion schema never does.
 */
export function computeScopeHash(scope: HashableScope): string {
  const content: Record<string, unknown> = { ...scope };
  delete content.id;
  delete content.createdAt;
  delete content.hash;
  return sha256Hex(FORMAT_TAG + canonicalJson(content));
}