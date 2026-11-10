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
    SpinnerContextProvider: function() {
        return _SpinnerContext.SpinnerContextProvider;
    },
    useSpinnerContext: function() {
        return _SpinnerContext.useSpinnerContext;
    }
});
const _SpinnerContext = require("./SpinnerContext");
