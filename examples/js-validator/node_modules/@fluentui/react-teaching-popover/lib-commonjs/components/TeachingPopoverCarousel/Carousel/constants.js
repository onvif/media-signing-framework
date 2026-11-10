"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    CAROUSEL_ACTIVE_ITEM: function() {
        return CAROUSEL_ACTIVE_ITEM;
    },
    CAROUSEL_ITEM: function() {
        return CAROUSEL_ITEM;
    }
});
const CAROUSEL_ITEM = 'data-carousel-item';
const CAROUSEL_ACTIVE_ITEM = 'data-carousel-active-item';
