import {
  ScopeVersion,
  type RawRule,
  type Protocol,
  type ToolClass,
} from './types';
import { normalizeDomain, normalizeWildcard } from './normalize';
import { parseIp, parseCidr } from './ip';
import { normalizeUrlPrefix } from './url';
import { computeScopeHash } from './hash';

type RawBaseRule = {
  readonly id: string;
  readonly effect: RawRule['effect'];
  readonly ports?: readonly number[];
  readonly protocols?: readonly Protocol[];
  readonly toolClasses?: readonly ToolClass[];
};

type CompiledTarget =
  | { targetType: 'domain'; host: string }
  | { targetType: 'wildcard'; base: string }
  | { targetType: 'ip'; version: 4 | 6; value: bigint }
  | { targetType: 'cidr'; version: 4 | 6; network: bigint; prefix: number }
  | {
      targetType: 'url_prefix';
      scheme: 'http' | 'https';
      host: string;
      port: number;
      path: string;
    };

export type CompiledRule = RawBaseRule & CompiledTarget;

export type CompileResult =
  | { ok: true; rule: CompiledRule }
  | { ok: false; ruleId: string; message: string };

const show = (s: string) => JSON.stringify(s.slice(0, 80));

/**
 * Compiles a single RawRule into an in-memory CompiledRule.
 * Returns { ok: false, ruleId, message } if pattern normalization/parsing fails.
 */
export function compileRule(rule: RawRule): CompileResult {
  const base: RawBaseRule = {
    id: rule.id,
    effect: rule.effect,
    ...(rule.ports !== undefined
      ? { ports: Object.freeze([...rule.ports]) }
      : {}),
    ...(rule.protocols !== undefined
      ? { protocols: Object.freeze([...rule.protocols]) }
      : {}),
    ...(rule.toolClasses !== undefined
      ? { toolClasses: Object.freeze([...rule.toolClasses]) }
      : {}),
  };

  switch (rule.targetType) {
    case 'domain': {
      const res = normalizeDomain(rule.pattern);
      if (!res.ok) {
        return {
          ok: false,
          ruleId: rule.id,
          message: `Invalid domain pattern ${show(rule.pattern)}`,
        };
      }
      return {
        ok: true,
        rule: Object.freeze({ ...base, targetType: 'domain', host: res.value }),
      };
    }

    case 'wildcard': {
      const res = normalizeWildcard(rule.pattern);
      if (!res.ok) {
        return {
          ok: false,
          ruleId: rule.id,
          message: `Invalid wildcard pattern ${show(rule.pattern)}`,
        };
      }
      return {
        ok: true,
        rule: Object.freeze({
          ...base,
          targetType: 'wildcard',
          base: res.value,
        }),
      };
    }

    case 'ip': {
      const ip = parseIp(rule.pattern);
      if (ip === null) {
        return {
          ok: false,
          ruleId: rule.id,
          message: `Invalid IP address pattern ${show(rule.pattern)}`,
        };
      }
      return {
        ok: true,
        rule: Object.freeze({
          ...base,
          targetType: 'ip',
          version: ip.version,
          value: ip.value,
        }),
      };
    }

    case 'cidr': {
      const cidr = parseCidr(rule.pattern);
      if (cidr === null) {
        return {
          ok: false,
          ruleId: rule.id,
          message: `Invalid CIDR pattern ${show(rule.pattern)}`,
        };
      }
      return {
        ok: true,
        rule: Object.freeze({
          ...base,
          targetType: 'cidr',
          version: cidr.version,
          network: cidr.network,
          prefix: cidr.prefix,
        }),
      };
    }

    case 'url_prefix': {
      const res = normalizeUrlPrefix(rule.pattern);
      if (!res.ok) {
        return {
          ok: false,
          ruleId: rule.id,
          message: `Invalid URL prefix pattern ${show(rule.pattern)}`,
        };
      }

      let u: URL;
      try {
        u = new URL(res.value);
      } catch {
        return {
          ok: false,
          ruleId: rule.id,
          message: 'URL prefix failed to re-parse after normalization',
        };
      }
      const scheme = u.protocol === 'https:' ? 'https' : 'http';
      const port = u.port ? Number(u.port) : scheme === 'https' ? 443 : 80;
      // IPv6 hosts keep their brackets in URL.hostname; rules store them bare.
      const host = u.hostname.startsWith('[')
        ? u.hostname.slice(1, -1)
        : u.hostname;

      return {
        ok: true,
        rule: Object.freeze({
          ...base,
          targetType: 'url_prefix',
          scheme,
          host,
          port,
          path: u.pathname,
        }),
      };
    }

    default: {
      const unreachable: never = rule.targetType;
      return {
        ok: false,
        ruleId: rule.id,
        message: `Unknown target type ${show(String(unreachable))}`,
      };
    }
  }
}

export type CompiledScope = {
  id: string;
  engagementId: string;
  notBefore: number;
  notAfter: number;
  hash: string;
  createdAt: number;
  rules: readonly CompiledRule[];
};

export type CompileError = { ruleId?: string; message: string };

export type CompileScopeResult =
  { ok: true; scope: CompiledScope } | { ok: false; errors: CompileError[] };

/**
 * Compiles an entire ScopeVersion into an in-memory CompiledScope.
 * Collects and returns all rule errors if any fail.
 */
export function compileScope(input: unknown): CompileScopeResult {
  // The ScopeVersion type is compile-time only. Re-validate so the schema
  // invariants (unique rule ids, valid window) hold for data from the API or DB.
  const parsed = ScopeVersion.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      errors: parsed.error.issues.map(issue => ({
        message: `${issue.path.map(String).join('.') || '(root)'}: ${issue.message}`,
      })),
    };
  }
  const scope = parsed.data;

  const rules: CompiledRule[] = [];
  const errors: CompileError[] = [];

  for (const rawRule of scope.rules) {
    const result = compileRule(rawRule);
    if (!result.ok) {
      errors.push({ ruleId: result.ruleId, message: result.message });
    } else {
      rules.push(result.rule);
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  // Checked last, so authors see rule errors first. A stale hash after editing
  // a bad rule is expected and not worth reporting alongside it.
  let expectedHash: string;
  try {
    expectedHash = computeScopeHash(scope);
  } catch {
    return {
      ok: false,
      errors: [{ message: 'hash: scope content could not be serialized' }],
    };
  }
  if (scope.hash !== expectedHash) {
    return {
      ok: false,
      errors: [
        {
          message: `hash: does not match the scope content (expected ${expectedHash})`,
        },
      ],
    };
  }

  return {
    ok: true,
    scope: Object.freeze({
      id: scope.id,
      engagementId: scope.engagementId,
      notBefore: scope.notBefore,
      notAfter: scope.notAfter,
      // TODO(hash): recompute from the canonical serialization and reject on mismatch.
      hash: scope.hash,
      createdAt: scope.createdAt,
      rules: Object.freeze(rules),
    }),
  };
}
