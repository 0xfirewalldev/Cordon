import { z } from 'zod';

const Id = z
  .string()
  .min(1, 'ID is required')
  .max(255, 'ID cannot exceed 255 characters');
const Sha256Hash = z
  .string()
  .regex(/^[a-f0-9]{64}$/, 'Must be a lowercase SHA-256 hex digest');
const EpochMs = z.number().int().nonnegative();

export const TargetType = z.enum([
  'domain',
  'wildcard',
  'ip',
  'cidr',
  'url_prefix',
]);
export type TargetType = z.infer<typeof TargetType>;

export const Effect = z.enum(['include', 'exclude']);
export type Effect = z.infer<typeof Effect>;

export const ToolClass = z.enum([
  'passive',
  'active-light',
  'active-intrusive',
]);
export type ToolClass = z.infer<typeof ToolClass>;

export const Protocol = z.enum([
  'http',
  'https',
  'ftp',
  'ssh',
  'smtp',
  'imap',
  'pop3',
]);
export type Protocol = z.infer<typeof Protocol>;

export const ReasonCode = z.enum([
  'NO_INCLUDE_MATCH',
  'EXCLUDED',
  'OUTSIDE_WINDOW',
  'INVALID_TARGET',
  'TOOL_CLASS_NOT_ALLOWED',
  'PORT_NOT_ALLOWED',
  'RESOLVED_IP_OUT_OF_SCOPE',
  'INCLUDED',
]);
export type ReasonCode = z.infer<typeof ReasonCode>;

export const Decision = z
  .object({
    allowed: z.boolean(),
    reasons: z.array(ReasonCode).min(1, 'At least one reason is required'),
    matchedRuleIds: z.array(Id),
    scopeVersionHash: Sha256Hash,
    evaluatedAt: EpochMs,
  })
  .strict()
  .superRefine((d, ctx) => {
    const hasIncluded = d.reasons.includes('INCLUDED');
    if (d.allowed && (!hasIncluded || d.reasons.length > 1)) {
      ctx.addIssue({
        code: 'custom',
        path: ['reasons'],
        message: 'an allowed decision must have INCLUDED as its only reason',
      });
    }
    if (!d.allowed && hasIncluded) {
      ctx.addIssue({
        code: 'custom',
        path: ['reasons'],
        message: 'a denied decision cannot have INCLUDED as a reason',
      });
    }
  });
export type Decision = z.infer<typeof Decision>;

export const RawRule = z
  .object({
    id: Id,
    targetType: TargetType,
    effect: Effect,
    pattern: z
      .string()
      .min(1, 'Rule pattern is required')
      .max(1024, 'Rule pattern cannot exceed 1024 characters'),
    // absent = any; an empty array is invalid so it can't be misread
    toolClasses: z
      .array(ToolClass)
      .min(1)
      .max(ToolClass.options.length)
      .optional(),
    ports: z
      .array(z.number().int().min(1).max(65535))
      .min(1)
      .max(100)
      .optional(),
    protocols: z.array(Protocol).min(1).max(Protocol.options.length).optional(),
    notes: z.string().max(500, 'Notes cannot exceed 500 characters').optional(),
  })
  .strict();
export type RawRule = z.infer<typeof RawRule>;

export const ScopeVersion = z
  .object({
    id: Id,
    engagementId: Id,
    rules: z
      .array(RawRule)
      .max(10_000, 'A scope version cannot exceed 10,000 rules'),
    notBefore: EpochMs,
    notAfter: EpochMs,
    hash: Sha256Hash,
    createdAt: EpochMs,
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.notBefore >= v.notAfter) {
      ctx.addIssue({
        code: 'custom',
        path: ['notAfter'],
        message: 'must be after notBefore',
      });
    }

    const seen = new Set<string>();
    v.rules.forEach((rule, index) => {
      if (seen.has(rule.id)) {
        ctx.addIssue({
          code: 'custom',
          path: ['rules', index, 'id'],
          message: `duplicate rule id "${rule.id}"`,
        });
      }
      seen.add(rule.id);
    });
  });
export type ScopeVersion = z.infer<typeof ScopeVersion>;