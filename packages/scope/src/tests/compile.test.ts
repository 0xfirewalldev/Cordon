import { describe, expect, it } from 'vitest';
import { compileRule, compileScope } from '../compile';
import type { RawRule } from '../types';
import { sampleRules, sampleScopeVersion } from '../__fixtures__/rules';

describe('compileRule: target types', () => {
  it('compiles domain rules into canonical host', () => {
    const rule: RawRule = {
      id: 'r-domain',
      targetType: 'domain',
      effect: 'include',
      pattern: 'EXAMPLE.com.',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-domain',
        effect: 'include',
        targetType: 'domain',
        host: 'example.com',
      },
    });
  });

  it('fails domain rule with invalid pattern', () => {
    const rule: RawRule = {
      id: 'r-domain-bad',
      targetType: 'domain',
      effect: 'include',
      pattern: 'bad_domain.com',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: false,
      ruleId: 'r-domain-bad',
      message: 'Invalid domain pattern "bad_domain.com"',
    });
  });

  it('compiles wildcard rules into stripped base domain', () => {
    const rule: RawRule = {
      id: 'r-wildcard',
      targetType: 'wildcard',
      effect: 'include',
      pattern: '*.Example.COM',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-wildcard',
        effect: 'include',
        targetType: 'wildcard',
        base: 'example.com',
      },
    });
  });

  it('fails wildcard rule without leading *.', () => {
    const rule: RawRule = {
      id: 'r-wildcard-bad',
      targetType: 'wildcard',
      effect: 'include',
      pattern: 'example.com',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: false,
      ruleId: 'r-wildcard-bad',
      message: 'Invalid wildcard pattern "example.com"',
    });
  });

  it('fails wildcard rule for single-label base (*.com)', () => {
    const rule: RawRule = {
      id: 'r-wildcard-tld',
      targetType: 'wildcard',
      effect: 'include',
      pattern: '*.com',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: false,
      ruleId: 'r-wildcard-tld',
      message: 'Invalid wildcard pattern "*.com"',
    });
  });

  it('compiles IPv4 rules into numeric bigint value', () => {
    const rule: RawRule = {
      id: 'r-ip4',
      targetType: 'ip',
      effect: 'exclude',
      pattern: '203.0.113.5',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-ip4',
        effect: 'exclude',
        targetType: 'ip',
        version: 4,
        value: 3405803781n,
      },
    });
  });

  it('compiles IPv6 rules into numeric bigint value', () => {
    const rule: RawRule = {
      id: 'r-ip6',
      targetType: 'ip',
      effect: 'exclude',
      pattern: '::1',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-ip6',
        effect: 'exclude',
        targetType: 'ip',
        version: 6,
        value: 1n,
      },
    });
  });

  it('compiles IPv4-mapped IPv6 rule (::ffff:10.0.0.1) into version 4', () => {
    const rule: RawRule = {
      id: 'r-ip-mapped',
      targetType: 'ip',
      effect: 'exclude',
      pattern: '::ffff:10.0.0.1',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-ip-mapped',
        effect: 'exclude',
        targetType: 'ip',
        version: 4,
        value: 0x0a000001n, // 10.0.0.1 = 167772161n
      },
    });
  });

  it('collapses a mapped IPv6 URL host to IPv4', () => {
    const rule: RawRule = {
      id: 'r-url-mapped',
      targetType: 'url_prefix',
      effect: 'exclude',
      pattern: 'https://[::ffff:10.0.0.1]/x',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-url-mapped',
        effect: 'exclude',
        targetType: 'url_prefix',
        scheme: 'https',
        host: '10.0.0.1',
        port: 443,
        path: '/x',
      },
    });
  });

  it('fails IP rule with invalid pattern', () => {
    const rule: RawRule = {
      id: 'r-ip-bad',
      targetType: 'ip',
      effect: 'exclude',
      pattern: '127.1',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: false,
      ruleId: 'r-ip-bad',
      message: 'Invalid IP address pattern "127.1"',
    });
  });

  it('compiles IPv4 CIDR rules into network bigint and prefix length', () => {
    const rule: RawRule = {
      id: 'r-cidr4',
      targetType: 'cidr',
      effect: 'include',
      pattern: '198.51.100.0/24',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-cidr4',
        effect: 'include',
        targetType: 'cidr',
        version: 4,
        network: 3325256704n,
        prefix: 24,
      },
    });
  });

  it('compiles IPv6 CIDR rules into exact network bigint and prefix length', () => {
    const rule: RawRule = {
      id: 'r-cidr6',
      targetType: 'cidr',
      effect: 'include',
      pattern: '2001:db8::/32',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-cidr6',
        effect: 'include',
        targetType: 'cidr',
        version: 6,
        network: 0x20010db8n << 96n,
        prefix: 32,
      },
    });
  });

  it('fails CIDR rule with host bits set', () => {
    const rule: RawRule = {
      id: 'r-cidr-bad',
      targetType: 'cidr',
      effect: 'include',
      pattern: '198.51.100.1/24',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: false,
      ruleId: 'r-cidr-bad',
      message: 'Invalid CIDR pattern "198.51.100.1/24"',
    });
  });

  it('compiles URL prefix rules with default port and normalized path', () => {
    const rule: RawRule = {
      id: 'r-url-https',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://EXAMPLE.com/a/../admin',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-url-https',
        effect: 'include',
        targetType: 'url_prefix',
        scheme: 'https',
        host: 'example.com',
        port: 443,
        path: '/admin',
      },
    });
  });

  it('compiles URL prefix variants (http default port, custom http port, IPv4 host)', () => {
    const httpDefault: RawRule = {
      id: 'r-url-http-80',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'http://example.com:80/x',
    };
    expect(compileRule(httpDefault)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-url-http-80',
        effect: 'include',
        targetType: 'url_prefix',
        scheme: 'http',
        host: 'example.com',
        port: 80,
        path: '/x',
      },
    });

    const httpCustom: RawRule = {
      id: 'r-url-http-custom',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'http://example.com:8080/x',
    };
    expect(compileRule(httpCustom)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-url-http-custom',
        effect: 'include',
        targetType: 'url_prefix',
        scheme: 'http',
        host: 'example.com',
        port: 8080,
        path: '/x',
      },
    });

    const ipv4Host: RawRule = {
      id: 'r-url-ipv4',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'http://192.168.1.1:8080/admin',
    };
    expect(compileRule(ipv4Host)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-url-ipv4',
        effect: 'include',
        targetType: 'url_prefix',
        scheme: 'http',
        host: '192.168.1.1',
        port: 8080,
        path: '/admin',
      },
    });
  });

  it('compiles URL prefix rules with custom port and IPv6 host bare of brackets', () => {
    const rule: RawRule = {
      id: 'r-url-v6',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://[2001:db8::1]:8443/admin',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-url-v6',
        effect: 'include',
        targetType: 'url_prefix',
        scheme: 'https',
        host: '2001:db8::1',
        port: 8443,
        path: '/admin',
      },
    });
  });

  it('fails URL prefix rule with userinfo or fragments', () => {
    const userinfoRule: RawRule = {
      id: 'r-url-userinfo',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://user:pass@example.com/admin',
    };
    expect(compileRule(userinfoRule)).toStrictEqual({
      ok: false,
      ruleId: 'r-url-userinfo',
      message:
        'Invalid URL prefix pattern "https://user:pass@example.com/admin"',
    });

    const fragmentRule: RawRule = {
      id: 'r-url-frag',
      targetType: 'url_prefix',
      effect: 'include',
      pattern: 'https://example.com/admin#frag',
    };
    expect(compileRule(fragmentRule)).toStrictEqual({
      ok: false,
      ruleId: 'r-url-frag',
      message: 'Invalid URL prefix pattern "https://example.com/admin#frag"',
    });
  });

  it('fails-closed on unknown targetType cast', () => {
    const unknownRule = {
      id: 'r-unknown',
      targetType: 'bogus' as unknown as RawRule['targetType'],
      effect: 'include' as const,
      pattern: 'example.com',
    };
    expect(compileRule(unknownRule)).toStrictEqual({
      ok: false,
      ruleId: 'r-unknown',
      message: 'Unknown target type "bogus"',
    });
  });

  it('rejects cross-type confusion (domain rule given IP, cidr rule given domain)', () => {
    const domainWithIp: RawRule = {
      id: 'r-cross-1',
      targetType: 'domain',
      effect: 'include',
      pattern: '192.168.1.1',
    };
    expect(compileRule(domainWithIp)).toStrictEqual({
      ok: false,
      ruleId: 'r-cross-1',
      message: 'Invalid domain pattern "192.168.1.1"',
    });

    const cidrWithDomain: RawRule = {
      id: 'r-cross-2',
      targetType: 'cidr',
      effect: 'include',
      pattern: 'example.com',
    };
    expect(compileRule(cidrWithDomain)).toStrictEqual({
      ok: false,
      ruleId: 'r-cross-2',
      message: 'Invalid CIDR pattern "example.com"',
    });
  });

  it('sanitizes error messages containing newlines or long inputs', () => {
    const withNewline: RawRule = {
      id: 'r-newline',
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com\n',
    };
    const resNl = compileRule(withNewline);
    expect(resNl.ok).toBe(false);
    if (!resNl.ok) {
      expect(resNl.message).not.toMatch(/\n/);
      expect(resNl.message).toContain('\\n');
    }

    const longPattern = 'a'.repeat(1200);
    const withLong: RawRule = {
      id: 'r-long',
      targetType: 'domain',
      effect: 'include',
      pattern: longPattern,
    };
    const resLong = compileRule(withLong);
    expect(resLong.ok).toBe(false);
    if (!resLong.ok) {
      expect(resLong.message.length).toBeLessThan(120);
    }
  });
});

describe('compileRule: metadata and immutability', () => {
  it('preserves ports, protocols, toolClasses and omits notes', () => {
    const rule: RawRule = {
      id: 'r-meta',
      targetType: 'domain',
      effect: 'include',
      pattern: 'api.example.com',
      ports: [443, 8443],
      protocols: ['https'],
      toolClasses: ['passive', 'active-light'],
      notes: 'internal api recon',
    };
    expect(compileRule(rule)).toStrictEqual({
      ok: true,
      rule: {
        id: 'r-meta',
        effect: 'include',
        targetType: 'domain',
        host: 'api.example.com',
        ports: [443, 8443],
        protocols: ['https'],
        toolClasses: ['passive', 'active-light'],
      },
    });
  });

  it('defensively copies arrays and freezes compiled output against mutation', () => {
    const ports = [80, 443];
    const protocols: RawRule['protocols'] = ['https'];
    const toolClasses: RawRule['toolClasses'] = ['passive'];

    const raw: RawRule = {
      id: 'r-freeze',
      targetType: 'domain',
      effect: 'include',
      pattern: 'example.com',
      ports,
      protocols,
      toolClasses,
    };

    const res = compileRule(raw);
    expect(res.ok).toBe(true);
    if (res.ok) {
      ports.push(8080);
      protocols.push('http');
      toolClasses.push('active-light');

      expect(res.rule.ports).toStrictEqual([80, 443]);
      expect(res.rule.protocols).toStrictEqual(['https']);
      expect(res.rule.toolClasses).toStrictEqual(['passive']);
      expect(Object.isFrozen(res.rule)).toBe(true);
      expect(Object.isFrozen(res.rule.ports)).toBe(true);
    }
  });
});

describe('compileScope: valid input', () => {
  it.each(sampleRules)('compiles fixture $id ($targetType)', rule => {
    const res = compileRule(rule);
    expect(res.ok).toBe(true);
  });

  it('compiles sampleScopeVersion with all rules intact', () => {
    const res = compileScope(sampleScopeVersion);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.scope.id).toBe(sampleScopeVersion.id);
      expect(res.scope.engagementId).toBe(sampleScopeVersion.engagementId);
      expect(res.scope.notBefore).toBe(sampleScopeVersion.notBefore);
      expect(res.scope.notAfter).toBe(sampleScopeVersion.notAfter);
      expect(res.scope.hash).toBe(sampleScopeVersion.hash);
      expect(res.scope.createdAt).toBe(sampleScopeVersion.createdAt);
      expect(res.scope.rules).toHaveLength(sampleRules.length);
      expect(Object.isFrozen(res.scope)).toBe(true);
      expect(res.scope.rules.every(r => Object.isFrozen(r))).toBe(true);
    }
  });
});

describe('compileScope: invalid input & schema failures', () => {
  it('rejects non-object input', () => {
    const res = compileScope(null);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.errors.length).toBeGreaterThan(0);
    }
  });

  it('rejects an invalid window (notBefore >= notAfter)', () => {
    const invalid = {
      ...sampleScopeVersion,
      notBefore: sampleScopeVersion.notAfter + 1000,
    };
    const res = compileScope(invalid);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.errors[0]?.message).toMatch(
        /notAfter: must be after notBefore/
      );
    }
  });

  it('rejects duplicate rule IDs', () => {
    const dup = {
      ...sampleScopeVersion,
      rules: [sampleRules[0]!, sampleRules[0]!],
    };
    const res = compileScope(dup);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.errors[0]?.message).toMatch(/duplicate rule id/);
    }
  });
});

describe('compileScope: rule compilation errors', () => {
  it('collects all three rule errors in deterministic order when patterns fail', () => {
    const badScope = {
      ...sampleScopeVersion,
      rules: [
        { ...sampleRules[0]!, id: 'bad-1', pattern: 'bad_domain.com' },
        { ...sampleRules[1]!, id: 'bad-2', pattern: 'no-wildcard.com' },
        { ...sampleRules[2]!, id: 'bad-3', pattern: 'not.an.ip.address' },
      ],
    };
    const res = compileScope(badScope);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.errors).toHaveLength(3);
      expect(res.errors.map(e => e.ruleId)).toStrictEqual([
        'bad-1',
        'bad-2',
        'bad-3',
      ]);
    }
  });
});
