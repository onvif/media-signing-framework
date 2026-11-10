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
    OverridesContext: function() {
        return _OverridesContext.OverridesContext;
    },
    OverridesProvider: function() {
        return _OverridesContext.OverridesProvider;
    },
    useOverrides: function() {
        return _OverridesContext.useOverrides;
    }
});
const _OverridesContext = require("./OverridesContext");
