import type { RawRule, ScopeVersion } from '../types';

export const sampleRules = [
  {
    id: 'r-domain-apex',
    targetType: 'domain',
    effect: 'include',
    pattern: 'example.com',
  },
  {
    id: 'r-wildcard-sub',
    targetType: 'wildcard',
    effect: 'include',
    pattern: '*.example.com',
  },
  {
    id: 'r-ip-excluded',
    targetType: 'ip',
    effect: 'exclude',
    pattern: '203.0.113.5',
  },
  {
    id: 'r-cidr-excluded',
    targetType: 'cidr',
    effect: 'exclude',
    pattern: '198.51.100.0/24',
  },
  {
    id: 'r-url-admin',
    targetType: 'url_prefix',
    effect: 'exclude',
    pattern: 'https://example.com/admin',
  },

  // edge coverage
  {
    id: 'r-cidr6-included',
    targetType: 'cidr',
    effect: 'include',
    pattern: '2001:db8::/32',
  },
  {
    id: 'r-domain-api-https',
    targetType: 'domain',
    effect: 'include',
    pattern: 'api.example.com',
    ports: [443],
    protocols: ['https'],
  },
  {
    id: 'r-wildcard-passive',
    targetType: 'wildcard',
    effect: 'include',
    pattern: '*.passive.example.com',
    toolClasses: ['passive'],
    notes: 'passive recon only',
  },
] satisfies RawRule[];

export const sampleScopeVersion = {
  id: 'sv-fixture-1',
  engagementId: 'eng-fixture-1',
  rules: sampleRules,
  notBefore: Date.UTC(2026, 0, 1),
  notAfter: Date.UTC(2026, 11, 31),
  hash: '0'.repeat(64), // placeholder until the hashing function exists
  createdAt: Date.UTC(2026, 0, 1),
} satisfies ScopeVersion;
