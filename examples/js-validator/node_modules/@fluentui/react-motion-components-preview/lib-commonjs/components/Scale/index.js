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
    Scale: function() {
        return _Scale.Scale;
    },
    ScaleRelaxed: function() {
        return _Scale.ScaleRelaxed;
    },
    ScaleSnappy: function() {
        return _Scale.ScaleSnappy;
    }
});
const _Scale = require("./Scale");
