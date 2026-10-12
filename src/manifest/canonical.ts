// src/manifest/canonical.ts — RFC 8785 (JCS) canonical JSON for Trace Manifest.
// Isomorphic: no Node imports, runs in the browser and in Node.
import canonicalize from "canonicalize";

/** Optional limits, for callers that read untrusted data. The default is no limit, as before. */
export interface CanonicalOptions {
  /** Longest string (in UTF-16 code units) accepted anywhere, checked while the single read is made. */
  maxStringLength?: number;
}

/** Thrown when a CanonicalOptions limit is exceeded. The message names the path, never the value. */
export class CanonicalLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalLimitError";
  }
}

function fail(path: string, reason: string): never {
  // The message names where the problem is, never the value: manifest content may be case data.
  // Paths do contain property names; that is accepted because manifest keys are structural field
  // names, not case data.
  throw new Error(`canonicalizeJcs: ${reason} at ${path}`);
}

type DataDescriptor = PropertyDescriptor & { value: unknown };

/** Reads one own property exactly once, through its descriptor, and refuses accessors. */
function readDataProperty(obj: object, key: string, path: string): DataDescriptor | undefined {
  const desc = Object.getOwnPropertyDescriptor(obj, key);
  if (desc === undefined) return undefined;
  if (!("value" in desc)) fail(path, "accessor property is not allowed");
  return desc as DataDescriptor;
}

/**
 * Builds ONE validated deep copy of the input, reading every property exactly once. Only this copy
 * is handed to the engine, so validation and serialisation cannot see different data (a getter or
 * Proxy that answers differently on a second read gains nothing). Throws unless the input is made
 * only of strings, booleans, safe integers, plain arrays and plain objects with data properties.
 *
 * The copy's objects have a null prototype and are filled with defineProperty, so a JSON.parse
 * result with an own "__proto__" key keeps it as an ordinary key and no prototype is ever set. The
 * engine would otherwise silently drop undefined properties and turn holes into null, and honour
 * toJSON, any of which would let two different manifests share one hash.
 */
function snapshot(
  value: unknown,
  path: string,
  ancestors: Set<object>,
  maxStringLength: number,
): unknown {
  switch (typeof value) {
    case "string":
      // O(1): the length is read, the characters are not. Checked at the single read, before any serialising.
      if (value.length > maxStringLength)
        throw new CanonicalLimitError(
          `canonicalizeJcs: string longer than ${maxStringLength} characters at ${path}`,
        );
      return value; // lone surrogates in strings are rejected by the engine (RFC 8785 3.2.2.2)
    case "boolean":
      return value;
    case "number":
      if (Number.isNaN(value)) fail(path, "NaN is not allowed");
      if (!Number.isFinite(value)) fail(path, "Infinity is not allowed");
      if (!Number.isInteger(value)) fail(path, "non-integer number is not allowed");
      if (!Number.isSafeInteger(value)) fail(path, "integer outside the safe range is not allowed");
      return value;
    case "undefined":
      return fail(path, "undefined is not allowed");
    case "bigint":
      return fail(path, "bigint is not allowed; use a string of raw base units");
    case "function":
    case "symbol":
      return fail(path, `${typeof value} is not allowed`);
  }
  if (value === null) return fail(path, "null is not allowed");

  const obj = value as object;
  if (ancestors.has(obj)) fail(path, "cycle detected");
  ancestors.add(obj);
  let out: unknown;
  if (Array.isArray(obj)) {
    if (Object.getPrototypeOf(obj) !== Array.prototype) fail(path, "only plain arrays are allowed");
    if ("toJSON" in obj) fail(path, "toJSON is not allowed");
    // Nothing but the index keys and "length" may be present: no toJSON, no hidden extras.
    const length = (readDataProperty(obj, "length", path) as DataDescriptor).value as number;
    const extra = Reflect.ownKeys(obj).find((k) => k !== "length" && !isIndexBelow(k, length));
    if (extra !== undefined) fail(path, "extra array property is not allowed");
    const copy: unknown[] = [];
    for (let i = 0; i < length; i += 1) {
      const desc = readDataProperty(obj, String(i), `${path}[${i}]`);
      if (desc === undefined) fail(`${path}[${i}]`, "undefined is not allowed");
      copy.push(snapshot(desc.value, `${path}[${i}]`, ancestors, maxStringLength));
    }
    out = copy;
  } else {
    const proto = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) fail(path, "only plain objects are allowed");
    const copy = Object.create(null) as Record<string, unknown>;
    // A hidden property (non-enumerable or symbol-keyed) would be dropped by the copy, letting two
    // inputs that differ only in it share one hash. Refuse it, as arrays do.
    // The key list is read once, so the check and the copy see the same keys.
    for (const key of Reflect.ownKeys(obj)) {
      if (typeof key !== "string") fail(path, "non-enumerable or symbol property is not allowed");
      if (key.length > maxStringLength)
        throw new CanonicalLimitError(
          `canonicalizeJcs: property name longer than ${maxStringLength} characters at ${path}`,
        );
      const desc = readDataProperty(obj, key, `${path}.${key}`);
      if (desc === undefined) continue; // removed while iterating: not part of the data
      if (!desc.enumerable) fail(path, "non-enumerable or symbol property is not allowed");
      Object.defineProperty(copy, key, {
        value: snapshot(desc.value, `${path}.${key}`, ancestors, maxStringLength),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    out = copy;
  }
  ancestors.delete(obj);
  return out;
}

function isIndexBelow(key: string | symbol, length: number): boolean {
  if (typeof key !== "string") return false;
  const n = Number(key);
  return Number.isInteger(n) && n >= 0 && n < length && String(n) === key;
}

/**
 * Canonical JSON text per RFC 8785: keys sorted by UTF-16 code unit at every depth, ECMAScript number
 * serialisation, minimal string escaping, no whitespace. Pass UTF-8 bytes of the result to a hash.
 *
 * Stricter than the RFC on purpose, because a manifest holds none of these: throws on non-integer
 * numbers, integers outside the safe range, NaN, Infinity, undefined, null, bigint, functions,
 * symbols, array holes, cycles, accessor properties, arrays with extra properties or a toJSON, and
 * anything that is not a plain object, plain array, string, boolean or safe integer. Token amounts
 * are strings of raw base units.
 */
export function canonicalizeJcs(value: unknown, options: CanonicalOptions = {}): string {
  const maxStringLength = options.maxStringLength ?? Number.MAX_SAFE_INTEGER;
  const text = canonicalize(snapshot(value, "$", new Set(), maxStringLength));
  if (typeof text !== "string") fail("$", "value has no JSON representation");
  return text;
}
