import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../sha256';

describe('sha256Hex', () => {
  it('matches the published test vectors', () => {
    expect(sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('returns 64 lowercase hex characters and is deterministic', () => {
    const digest = sha256Hex('scope-guard');
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(sha256Hex('scope-guard')).toBe(digest);
    expect(sha256Hex('scope-guard ')).not.toBe(digest);
  });
});