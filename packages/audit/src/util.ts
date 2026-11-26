/** Escapes control characters and bounds length so untrusted values are safe in messages. */
export const show = (s: string): string => JSON.stringify(s.slice(0, 80));