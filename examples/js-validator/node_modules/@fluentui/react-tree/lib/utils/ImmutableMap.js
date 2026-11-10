import { _ as _define_property } from "@swc/helpers/_/_define_property";
const internalMapSymbol = Symbol('#internalMap');
let _internalMapSymbol = internalMapSymbol;
export class ImmutableMap {
    static dangerouslyGetInternalMap(immutableMap) {
        return immutableMap[internalMapSymbol];
    }
    static copy(immutableMap) {
        return this.from(immutableMap[internalMapSymbol]);
    }
    static from(iterable, mapFn) {
        if (iterable === undefined) {
            return this.empty;
        }
        if (!mapFn) {
            if (iterable instanceof this) {
                return iterable;
            }
            // casting here is ok, as the function overload ensures that the iterable is
            // Iterable<[unknown, unknown]>
            // if mapFn is not provided
            const iterableAsTuple = iterable;
            return new this(new Map(iterableAsTuple));
        }
        const map = new Map();
        for (const value of iterable){
            map.set(...mapFn(value));
        }
        return new this(map);
    }
    static [Symbol.hasInstance](instance) {
        return Boolean(typeof instance === 'object' && instance && internalMapSymbol in instance);
    }
    delete(key) {
        if (!this.has(key)) {
            return this;
        }
        const copy = ImmutableMap.copy(this);
        copy[internalMapSymbol].delete(key);
        return copy;
    }
    get(key) {
        return this[internalMapSymbol].get(key);
    }
    has(key) {
        return this[internalMapSymbol].has(key);
    }
    set(key, value) {
        if (this.get(key) === value) {
            return this;
        }
        const copy = ImmutableMap.copy(this);
        copy[internalMapSymbol].set(key, value);
        return copy;
    }
    [Symbol.iterator]() {
        return this[internalMapSymbol].entries();
    }
    /**
   * Do not use this constructor directly, use {@link ImmutableMap.from} instead.
   * {@link ImmutableMap.from} handles instance verification (which might be problematic on {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/instanceof#instanceof_and_multiple_realms | multiple realms}),
   * avoid unnecessary copies, supports iterables and ensures that the internal map is never exposed.
   *
   *⚠️⚠️  _By using this constructor directly, you might end up with a mutable map, as it is not guaranteed that the internal map is not exposed._ ⚠️⚠️
   */ constructor(internalMap){
        _define_property(this, "size", void 0);
        _define_property(this, _internalMapSymbol, void 0);
        this[internalMapSymbol] = internalMap;
        this.size = this[internalMapSymbol].size;
    }
}
_define_property(ImmutableMap, "empty", new ImmutableMap(new Map()));
