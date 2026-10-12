// A read-only view over a private Map. The program dictionary and the default decoder registry
// are shared by every caller in the process, so a caller must not be able to add, replace or remove an
// entry and thereby change what later transactions decode to. The view is a frozen object with no
// set/delete/clear and no way back to the Map behind it (a plain `Object.freeze(new Map())` would still
// accept `.set`). Pure and isomorphic.

export function readOnlyMap<K, V>(source: Iterable<readonly [K, V]>): ReadonlyMap<K, V> {
  const map = new Map<K, V>(source);
  const view: ReadonlyMap<K, V> = {
    get size() {
      return map.size;
    },
    get: (key) => map.get(key),
    has: (key) => map.has(key),
    forEach: (callback, thisArg) =>
      map.forEach((value, key) => callback.call(thisArg, value, key, view)),
    entries: () => map.entries(),
    keys: () => map.keys(),
    values: () => map.values(),
    [Symbol.iterator]: () => map[Symbol.iterator](),
  };
  return Object.freeze(view);
}
