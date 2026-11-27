import { CanonicalError, canonicalJson, sha256Hex } from '@scope-guard/canonical';
import { describe, expect, it } from 'vitest';
import { sampleRules, sampleScopeVersion } from '../__fixtures__/rules';
import { compileScope } from '../compile';
import { computeScopeHash } from '../hash';
import type { HashableScope } from '../hash';
import type { RawRule } from '../types';

const base: HashableScope = {
  engagementId: 'eng-1',
  notBefore: 1000,
  notAfter: 2000,
  rules: [
    { id: 'r1', targetType: 'domain', effect: 'include', pattern: 'example.com' },
    {
      id: 'r2',
      targetType: 'cidr',
      effect: 'exclude',
      pattern: '198.51.100.0/24',
      ports: [80, 443],
      notes: 'staging',
    },
  ],
};
const [r1, r2] = base.rules as [RawRule, RawRule];
const withRules = (rules: RawRule[]): HashableScope => ({ ...base, rules });

describe('computeScopeHash: format', () => {
  const single: HashableScope = {
    engagementId: 'eng-1',
    notBefore: 1000,
    notAfter: 2000,
    rules: [{ id: 'r1', targetType: 'domain', effect: 'include', pattern: 'example.com' }],
  };
  const canonical =
    '{"engagementId":"eng-1","notAfter":2000,"notBefore":1000,"rules":[{"effect":"include","id":"r1","pattern":"example.com","targetType":"domain"}]}';

  it('pins the format: tag, then canonical JSON of the content', () => {
    expect(canonicalJson(single)).toBe(canonical);
    expect(computeScopeHash(single)).toBe(
      sha256Hex(`scope-guard.scope.v1\n${canonical}`),
    );
    expect(computeScopeHash(single)).toBe(
      '780613a2e38cda1a0df3ab619157aa3a0c04f3e95c0c59a9836ab2c80fec8b16',
    );
  });

  it('returns 64 lowercase hex characters and is deterministic', () => {
    expect(computeScopeHash(base)).toMatch(/^[a-f0-9]{64}$/);
    expect(computeScopeHash(base)).toBe(computeScopeHash(base));
  });

  it('does not depend on key order', () => {
    const reordered = {
      rules: [
        { pattern: 'example.com', effect: 'include', targetType: 'domain', id: 'r1' },
        { notes: 'staging', ports: [80, 443], pattern: '198.51.100.0/24', effect: 'exclude', targetType: 'cidr', id: 'r2' },
      ],
      notAfter: 2000,
      engagementId: 'eng-1',
      notBefore: 1000,
    } as HashableScope;
    expect(computeScopeHash(reordered)).toBe(computeScopeHash(base));
  });

  it('treats an undefined optional property like an absent one', () => {
    const explicit = withRules([{ ...r1, ports: undefined } as RawRule, r2]);
    expect(computeScopeHash(explicit)).toBe(computeScopeHash(base));
  });

  it('ignores id, createdAt and hash', () => {
    expect(
      computeScopeHash({ ...base, id: 'sv-9', createdAt: 5, hash: 'f'.repeat(64) }),
    ).toBe(computeScopeHash(base));
  });

  it('does not mutate its input, and accepts frozen input', () => {
    const before = structuredClone(base);
    computeScopeHash(base);
    expect(base).toStrictEqual(before);
    const frozen = Object.freeze({
      ...base,
      rules: Object.freeze(base.rules.map((r) => Object.freeze({ ...r }))) as RawRule[],
    });
    expect(computeScopeHash(frozen)).toBe(computeScopeHash(base));
  });

  it('throws on content that cannot be serialized', () => {
    expect(() =>
      computeScopeHash({ ...base, notBefore: 1n as unknown as number }),
    ).toThrow(CanonicalError);
  });
});

describe('computeScopeHash: every part of the content is covered', () => {
  it.each([
    ['engagementId', { ...base, engagementId: 'eng-2' }],
    ['notBefore', { ...base, notBefore: 1001 }],
    ['notAfter', { ...base, notAfter: 2001 }],
    ['a rule id', withRules([{ ...r1, id: 'r9' }, r2])],
    ['a rule pattern', withRules([{ ...r1, pattern: 'example.org' }, r2])],
    ['a rule effect', withRules([{ ...r1, effect: 'exclude' }, r2])],
    ['a rule target type', withRules([{ ...r1, targetType: 'wildcard' }, r2])],
    ['a rule note', withRules([r1, { ...r2, notes: 'production' }])],
    ['a removed note', withRules([r1, { id: 'r2', targetType: 'cidr', effect: 'exclude', pattern: '198.51.100.0/24', ports: [80, 443] }])],
    ['a rule port', withRules([r1, { ...r2, ports: [80, 444] }])],
    ['port order', withRules([r1, { ...r2, ports: [443, 80] }])],
    ['an added protocol', withRules([{ ...r1, protocols: ['https'] }, r2])],
    ['an added tool class', withRules([{ ...r1, toolClasses: ['passive'] }, r2])],
    ['a removed rule', withRules([r1])],
    ['an added rule', withRules([r1, r2, { id: 'r3', targetType: 'ip', effect: 'exclude', pattern: '203.0.113.5' }])],
    ['rule order', withRules([r2, r1])],
  ])('changes when %s changes', (_label, changed) => {
    expect(computeScopeHash(changed)).not.toBe(computeScopeHash(base));
  });
});

describe('compileScope: hash verification', () => {
  const resealed = (change: Record<string, unknown>) => {
    const draft = { ...sampleScopeVersion, ...change };
    return { ...draft, hash: computeScopeHash(draft as HashableScope) };
  };

  it('accepts a version whose hash matches its content', () => {
    const result = compileScope(sampleScopeVersion);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.scope.hash).toBe(sampleScopeVersion.hash);
  });

  it('accepts an edit that was re-sealed', () => {
    expect(compileScope(resealed({ notAfter: sampleScopeVersion.notAfter + 1 })).ok).toBe(true);
    expect(compileScope(resealed({ engagementId: 'eng-other' })).ok).toBe(true);
  });

  it('does not cover id or createdAt, so changing them keeps the hash valid', () => {
    const result = compileScope({ ...sampleScopeVersion, id: 'sv-other', createdAt: 5 });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.scope.hash).toBe(sampleScopeVersion.hash);
  });

  it('rejects the old placeholder hash and names the expected one', () => {
    const result = compileScope({ ...sampleScopeVersion, hash: '0'.repeat(64) });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]?.ruleId).toBeUndefined();
      expect(result.errors[0]?.message).toMatch(/^hash: does not match/);
      expect(result.errors[0]?.message).toContain(computeScopeHash(sampleScopeVersion));
    }
  });

  it.each([
    ['a rule pattern', { rules: sampleRules.map((r, i) => (i === 0 ? { ...r, pattern: 'example.org' } : r)) }],
    ['a removed rule', { rules: sampleRules.slice(1) }],
    ['rule order', { rules: [...sampleRules].reverse() }],
    ['a rule note', { rules: sampleRules.map((r, i) => (i === 0 ? { ...r, notes: 'edited' } : r)) }],
    ['notAfter', { notAfter: sampleScopeVersion.notAfter + 1 }],
    ['notBefore', { notBefore: sampleScopeVersion.notBefore + 1 }],
    ['engagementId', { engagementId: 'eng-other' }],
  ])('rejects %s edited without re-sealing', (_label, change) => {
    const result = compileScope({ ...sampleScopeVersion, ...change });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]?.message).toMatch(/^hash: does not match/);
    }
  });

  it('reports rule errors before the hash', () => {
    const result = compileScope({
      ...sampleScopeVersion,
      rules: [{ ...sampleRules[0]!, id: 'bad', pattern: 'bad_domain.com' }],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]?.ruleId).toBe('bad');
      expect(result.errors[0]?.message).toMatch(/Invalid domain pattern/);
    }
  });

  it('reports schema errors before the hash', () => {
    const result = compileScope({
      ...sampleScopeVersion,
      notBefore: sampleScopeVersion.notAfter + 1,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors[0]?.message).toMatch(/notAfter: must be after notBefore/);
    }
  });
});