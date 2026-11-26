import { describe, expect, it } from 'vitest';
import { canonicalJson, CanonicalError } from '../canonical-json';

const nest = (levels: number): unknown => {
  let value: unknown = 1;
  for (let i = 0; i < levels; i++) value = [value];
  return value;
};

describe('canonicalJson: output', () => {
  it.each([
    [null, 'null'],
    [true, 'true'],
    [false, 'false'],
    [0, '0'],
    [-0, '0'],
    [1.5, '1.5'],
    [1e21, '1e+21'],
    ['x', '"x"'],
    ['', '""'],
    [[], '[]'],
    [{}, '{}'],
    [[1, [2, [3]]], '[1,[2,[3]]]'],
    [{ a: { b: { c: [] } } }, '{"a":{"b":{"c":[]}}}'],
    [[3, 1, 2], '[3,1,2]'],
  ])('%j -> %s', (value, expected) => {
    expect(canonicalJson(value)).toBe(expected);
  });

  it('sorts keys and does not depend on insertion order', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson({ a: 1, b: { d: 1, c: 2 } })).toBe(
      canonicalJson({ b: { c: 2, d: 1 }, a: 1 }),
    );
    expect(canonicalJson({ b: 1, a: 2, '': 0, B: 3 })).toBe(
      '{"":0,"B":3,"a":2,"b":1}',
    );
  });

  it('omits object properties that are undefined', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(canonicalJson({ a: 1, b: undefined })).toBe(canonicalJson({ a: 1 }));
  });

  it('serializes null-prototype objects', () => {
    const o = Object.create(null) as Record<string, unknown>;
    o.x = 1;
    expect(canonicalJson(o)).toBe('{"x":1}');
  });

  it('escapes strings and keys', () => {
    expect(canonicalJson('a"b\\c\n')).toBe('"a\\"b\\\\c\\n"');
    expect(canonicalJson({ 'a"b': 1 })).toBe('{"a\\"b":1}');
    expect(canonicalJson('é😀')).toBe('"é😀"');
  });

  it('escapes lone surrogates so the output is always well-formed', () => {
    expect(canonicalJson('\ud800')).toBe('"\\ud800"');
    expect(canonicalJson('\ud800')).not.toBe(canonicalJson('\ufffd'));
  });

  it('keeps an own "__proto__" key as data', () => {
    const o: unknown = JSON.parse('{"__proto__":1,"a":2}');
    expect(canonicalJson(o)).toBe('{"__proto__":1,"a":2}');
  });

  it('is stable across a JSON round trip', () => {
    const value = { z: [1, { y: 2, x: [true, null] }], a: 'é' };
    const once = canonicalJson(value);
    expect(canonicalJson(JSON.parse(once))).toBe(once);
  });

  it('does not mutate its input', () => {
    const value = { b: [1, 2], a: { d: 1, c: 2 } };
    const before = structuredClone(value);
    canonicalJson(value);
    expect(value).toStrictEqual(before);
  });
});

describe('canonicalJson: fails closed', () => {
  class Point {
    x = 1;
  }
  class Sub extends Array<number> {}

  const sparse = new Array<number>(3);
  const withExtra = Object.assign([1], { extra: 1 });
  const withGetter = Object.defineProperty({}, 'a', {
    get: () => 1,
    enumerable: true,
  });
  const withSymbolKey = { [Symbol('k')]: 1 };
  const cycleArray: unknown[] = [];
  cycleArray.push(cycleArray);
  const cycleObject: Record<string, unknown> = {};
  cycleObject.self = cycleObject;

  it.each([
    ['undefined', undefined],
    ['a function', () => 1],
    ['a symbol', Symbol('x')],
    ['a bigint', 1n],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
    ['a Date', new Date(0)],
    ['a Map', new Map()],
    ['a Set', new Set()],
    ['a RegExp', /re/],
    ['an Error', new Error('x')],
    ['a typed array', new Uint8Array(2)],
    ['a boxed number', Object(1)],
    ['a class instance', new Point()],
    ['an Array subclass', new Sub()],
    ['undefined inside an array', [1, undefined]],
    ['a sparse array', sparse],
    ['an array with extra properties', withExtra],
    ['a bigint inside an object', { a: 1n }],
    ['an accessor property', withGetter],
    ['a symbol key', withSymbolKey],
    ['an array cycle', cycleArray],
    ['an object cycle', cycleObject],
  ])('rejects %s', (_label, value) => {
    expect(() => canonicalJson(value)).toThrow(CanonicalError);
  });

  it('allows nesting up to the depth limit and rejects one level more', () => {
    expect(() => canonicalJson(nest(64))).not.toThrow();
    expect(() => canonicalJson(nest(65))).toThrow(CanonicalError);
  });

  it('reports where the problem is', () => {
    try {
      canonicalJson({ a: [1, Number.NaN] });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(CanonicalError);
      expect((error as CanonicalError).path).toBe('$["a"][1]');
    }
  });
});