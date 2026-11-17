import { describe, expect, it } from 'vitest';
import { RawRule, ScopeVersion } from '../types';
import { sampleRules, sampleScopeVersion } from '../__fixtures__/rules';

describe('fixtures stay valid against the schemas', () => {
  it.each(sampleRules.map(r => [r.id, r] as const))(
    'rule %s parses',
    (_id, rule) => {
      expect(RawRule.safeParse(rule).success).toBe(true);
    }
  );

  it('scope version parses', () => {
    expect(ScopeVersion.safeParse(sampleScopeVersion).success).toBe(true);
  });
});

describe('schema rejects bad input', () => {
  const base = sampleRules[0];

  it('rejects an array pattern', () => {
    expect(
      RawRule.safeParse({ ...base, pattern: [{ op: 'equals', value: 'x' }] })
        .success
    ).toBe(false);
  });

  it('rejects empty optional arrays', () => {
    expect(RawRule.safeParse({ ...base, ports: [] }).success).toBe(false);
    expect(RawRule.safeParse({ ...base, toolClasses: [] }).success).toBe(false);
    expect(RawRule.safeParse({ ...base, protocols: [] }).success).toBe(false);
  });

  it('rejects unknown keys', () => {
    expect(RawRule.safeParse({ ...base, extra: true }).success).toBe(false);
  });

  it('rejects out-of-range ports', () => {
    expect(RawRule.safeParse({ ...base, ports: [0] }).success).toBe(false);
    expect(RawRule.safeParse({ ...base, ports: [65536] }).success).toBe(false);
  });

  it('rejects duplicate rule ids', () => {
    const dup = { ...sampleScopeVersion, rules: [base, base] };
    expect(ScopeVersion.safeParse(dup).success).toBe(false);
  });

  it('rejects an inverted window', () => {
    const bad = {
      ...sampleScopeVersion,
      notBefore: sampleScopeVersion.notAfter,
    };
    expect(ScopeVersion.safeParse(bad).success).toBe(false);
  });
});
