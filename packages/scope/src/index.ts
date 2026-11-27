/**
 * @scope-guard/scope
 *
 * Fast, deterministic, fail-closed scope evaluation engine for security testing
 * and network traffic gating.
 */

// ============================================================================
// 1. Core Evaluation & Compilation API
// ============================================================================
export { evaluate } from './evaluate';
export { compileScope, compileRule } from './compile';
export type {
  CompiledScope,
  CompiledRule,
  CompileScopeResult,
  CompileResult,
  CompileError,
} from './compile';
export { computeScopeHash } from './hash';
export type { HashableScope } from './hash';

// ============================================================================
// 2. Target Parsing & Normalization
// ============================================================================
export { parseTarget } from './parse-target';
export type { ParseTargetResult } from './parse-target';
export { hostToString } from './format';

export type {
  Target,
  HostRef,
  IpHost,
  Resolution,
  EvalContext,
  MatchContext,
} from './target';

// ============================================================================
// 3. Schema & Domain Models (Zod & Inferred Types)
// ============================================================================
export {
  RawRule,
  ScopeVersion,
  Decision,
  ReasonCode,
  TargetType,
  Effect,
  ToolClass,
  Protocol,
} from './types';

export type {
  RawRule as RawRuleType,
  ScopeVersion as ScopeVersionType,
  Decision as DecisionType,
  ReasonCode as ReasonCodeType,
  TargetType as TargetTypeEnum,
  Effect as EffectEnum,
  ToolClass as ToolClassEnum,
  Protocol as ProtocolEnum,
} from './types';

// ============================================================================
// 4. Low-Level Canonical Normalizers & Parsers
// ============================================================================
export {
  normalizeDomain,
  normalizeWildcard,
  isValidAsciiHostname,
} from './normalize';
export type { NormalizeResult } from './normalize';

export { parseIp, normalizeIp, parseCidr, normalizeCidr } from './ip';
export type { ParsedIp, ParsedCidr } from './ip';

export { normalizeUrlPrefix } from './url';

// ============================================================================
// 5. Matchers
// ============================================================================
export { evaluateInclude, evaluateExclude } from './match';
export type { IncludeResult, ConstraintReason } from './match';
