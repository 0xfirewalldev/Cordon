/**
 * Deterministic JSON for hashing. Fails closed: anything without exactly one
 * unambiguous serialization throws instead of being coerced.
 *
 * Accepted: null, booleans, finite numbers, strings, arrays without holes,
 * and plain objects (prototype Object.prototype or null) with own enumerable
 * string keys and data properties.
 *
 * Rejected, so two different values can never share a serialization:
 * undefined, NaN, Infinity, bigint, symbol, function, Date, Map, Set, boxed
 * primitives, class instances, sparse arrays, arrays with extra properties,
 * symbol keys, accessor properties, and nesting deeper than MAX_DEPTH
 * (which also stops cycles).
 *
 * Deliberate choices:
 * - Object properties whose value is undefined are omitted, as JSON.stringify
 *   does. undefined inside an array, or at the top level, throws.
 * - -0 serializes as 0.
 * - Keys are sorted by UTF-16 code unit order (the default sort).
 * - Lone surrogates are escaped (\ud800), so the output is always well-formed
 *   and hashes identically no matter how a string was built.
 */

export class CanonicalError extends Error {
  readonly path: string;

  constructor(message: string, path: string) {
    super(`${message} at ${path}`);
    this.name = 'CanonicalError';
    this.path = path;
  }
}

const MAX_DEPTH = 64;
const MAX_KEY_IN_PATH = 40;

function serialize(value: unknown, depth: number, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalError('Non-finite number', path);
      }
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      // undefined, bigint, symbol, function
      throw new CanonicalError(`Unsupported type ${typeof value}`, path);
  }

  if (depth >= MAX_DEPTH) {
    throw new CanonicalError(`Nesting deeper than ${MAX_DEPTH}`, path);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new CanonicalError('Symbol keys are not allowed', path);
  }

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new CanonicalError('Array subclass', path);
    }
    // Holes and extra properties both make this differ from the array length.
    if (Object.keys(value).length !== value.length) {
      throw new CanonicalError('Sparse array or array with extra properties', path);
    }
    const items = value.map((item, i) =>
      serialize(item, depth + 1, `${path}[${i}]`),
    );
    return `[${items.join(',')}]`;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new CanonicalError('Only plain objects are allowed', path);
  }

  const entries: string[] = [];
  for (const key of Object.keys(value).sort()) {
    const keyPath = `${path}[${JSON.stringify(key.slice(0, MAX_KEY_IN_PATH))}]`;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new CanonicalError('Accessor properties are not allowed', keyPath);
    }
    if (descriptor.value === undefined) continue;
    entries.push(
      `${JSON.stringify(key)}:${serialize(descriptor.value, depth + 1, keyPath)}`,
    );
  }
  return `{${entries.join(',')}}`;
}

export function canonicalJson(value: unknown): string {
  return serialize(value, 0, '$');
}