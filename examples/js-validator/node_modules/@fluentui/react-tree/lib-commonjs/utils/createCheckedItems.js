"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "createCheckedItems", {
    enumerable: true,
    get: function() {
        return createCheckedItems;
    }
});
const _ImmutableMap = require("./ImmutableMap");
const tuplifyCheckedItem = (value)=>Array.isArray(value) ? value : [
        value,
        true
    ];
const createCheckedItems = (iterable)=>_ImmutableMap.ImmutableMap.from(iterable, tuplifyCheckedItem);
