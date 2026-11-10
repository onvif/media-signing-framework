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
    Provider: function() {
        return _ProviderContext.Provider;
    },
    useFluent: function() {
        return _ProviderContext.useFluent;
    }
});
const _ProviderContext = require("./ProviderContext");
