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
    clampMax: function() {
        return _clampMax.clampMax;
    },
    clampValue: function() {
        return _clampValue.clampValue;
    }
});
const _clampMax = require("./clampMax");
const _clampValue = require("./clampValue");
