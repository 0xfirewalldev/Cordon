import { z } from 'zod';

export const Id = z
  .string()
  .min(1, 'ID is required')
  .max(255, 'ID cannot exceed 255 characters');

export const Sha256Hash = z
  .string()
  .regex(/^[a-f0-9]{64}$/, 'Must be a lowercase SHA-256 hex digest');

export const EpochMs = z.number().int().nonnegative();
