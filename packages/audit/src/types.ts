import { z } from 'zod';

export const AuditRecord = z.enum([
  'engagementId',
  'seq',
  'prevHash',
  'hash',
  'timestamp',
  'actor',
  'type',
  'payload',
]);
export type AuditRecord = z.infer<typeof AuditRecord>

export const AuditEvent = z.object({
    key: AuditRecord,
    value: z.any()
})

export const AuditTargetSchema = z.object({
  ruleId: z.string().optional(),
  toolClass: z
    .enum(['browser-automation', 'server-component', 'server-side-function'])
    .optional(),
  port: z.number().optional(),
  scopeId: z.string().optional(),
  toolId: z.string().optional(),
  isProduction: z.boolean().optional(),
});

export const AuditResultSchema = z.object({
  id: z.string(),
  createdAt: z.string().transform(val => new Date(val)),
  modifiedAt: z.string().transform(val => new Date(val)),
  version: z.number(),
  scopeVersion: z.string(),
  scopeId: z.string(),
  rules: z.array(z.string()),
  domain: z.string(),
  target: z.string(),
  ip: z.string(),
  toolClass: z.string(),
  port: z.number(),
  protocol: z.string(),
  toolId: z.string(),
  organizationId: z.string(),
  isProduction: z.boolean(),
  decision: z.enum(['ALLOW', 'BLOCK']),
  reasonCode: z.enum([
    'UNKNOWN',
    'NOT_IN_SCOPE',
    'OUTSIDE_TTL',
    'OUTSIDE_DNS_TREE',
  ]),
  effectiveIp: z.string(),
  effectivePort: z.number(),
  effectiveProtocol: z.string(),
  dnsTree: z.any(),
  windowNs: z.string(),
  includedBy: z.array(z.string()),
  excludedBy: z.array(z.string()),
  windowMs: z.number(),
  dnsHops: z.number(),
  ttl: z.number(),
  ttlSec: z.number(),
});
