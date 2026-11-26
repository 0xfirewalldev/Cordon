import { createHash } from 'node:crypto';

/**
 * SHA-256 of UTF-8 text, as lowercase hex. Feed it canonicalJson output:
 * that is always well-formed, so a lone surrogate can't be silently replaced
 * during encoding and make two different strings hash the same.
 */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}