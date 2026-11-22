/** Escapes control characters and bounds length so untrusted input is safe to log. */
export const show = (s: string): string => JSON.stringify(s.slice(0, 80));