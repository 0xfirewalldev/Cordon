export {
  AuthFailurePayload,
  DecisionPayload,
  EngagementStatusChangedPayload,
  RunFinishedPayload,
  RunStartedPayload,
  ScopeVersionApprovedPayload,
  ScopeVersionCreatedPayload,
} from './events';

export {
  Actor,
  AuditEvent,
  AuditRecord,
  type AuditEventType,
} from './types';

export {
  GENESIS_PREV_HASH,
  verifyChain,
  type ChainErrorCode,
  type ChainHead,
  type ChainPosition,
  type ChainVerifyResult,
  type VerifyOptions,
} from './chain';

export {
  SequenceConflictError,
  type AuditStore,
  type ListOptions,
} from './store';

export {
  createAuditLog,
  type AppendErrorCode,
  type AppendResult,
  type AuditLog,
  type AuditLogOptions,
  type VerifyLogOptions,
} from './log';

export {
  REDACTED_VALUE,
  redactRecord,
  redactRecords,
  type RedactedRecord,
  type RedactOptions,
} from './redact';

// buildRecord, computeRecordHash, UnsignedRecord, InMemoryAuditStore, createMemoryStore,
// EpochMs, Id, and Sha256Hash are intentionally NOT exported from the public entry-point.
// - Use AuditLog.append as the only write path.
// - Import InMemoryAuditStore / createMemoryStore from '@scope-guard/audit/testing' in tests.
