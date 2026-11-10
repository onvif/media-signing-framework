"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "ImmutableSet", {
    enumerable: true,
    get: function() {
        return ImmutableSet;
    }
});
const _define_property = require("@swc/helpers/_/_define_property");
const internalSetSymbol = Symbol('#internalSet');
let _internalSetSymbol = internalSetSymbol;
class ImmutableSet {
    static dangerouslyGetInternalSet(set) {
        return set[internalSetSymbol];
    }
    static copy(immutableSet) {
        return new ImmutableSet(new Set(immutableSet[internalSetSymbol]));
    }
    /**
   * Creates a new {@link ImmutableSet} from an iterable.
   * If the iterable is undefined, {@link ImmutableSet.empty} will be returned.
   * If the iterable is already an {@link ImmutableSet}, it will be returned as is no copy will be made.
   */ static from(iterable) {
        if (iterable === undefined) {
            return this.empty;
        }
        if (iterable instanceof this) {
            return iterable;
        }
        return new this(new Set(iterable));
    }
    static [Symbol.hasInstance](instance) {
        return Boolean(typeof instance === 'object' && instance && internalSetSymbol in instance);
    }
    add(value) {
        if (this.has(value)) {
            return this;
        }
        const copy = ImmutableSet.copy(this);
        copy[internalSetSymbol].add(value);
        return copy;
    }
    delete(value) {
        if (!this.has(value)) {
            return this;
        }
        const copy = ImmutableSet.copy(this);
        copy[internalSetSymbol].delete(value);
        return copy;
    }
    has(value) {
        return this[internalSetSymbol].has(value);
    }
    [Symbol.iterator]() {
        return this[internalSetSymbol].values();
    }
    /**
   * Do not use this constructor directly, use {@link ImmutableSet.from} instead.
   * {@link ImmutableSet.from} handles instance verification (which might be problematic on {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/instanceof#instanceof_and_multiple_realms | multiple realms}),
   * avoid unnecessary copies, supports iterables and ensures that the internal set is never exposed.
   *
   *⚠️⚠️  _By using this constructor directly, you might end up with a mutable set, as it is not guaranteed that the internal set is not exposed._ ⚠️⚠️
   */ constructor(internalSet){
        (0, _define_property._)(this, "size", void 0);
        (0, _define_property._)(this, _internalSetSymbol, void 0);
        this[internalSetSymbol] = internalSet;
        this.size = this[internalSetSymbol].size;
    }
}
(0, _define_property._)(ImmutableSet, "empty", new ImmutableSet(new Set()));
