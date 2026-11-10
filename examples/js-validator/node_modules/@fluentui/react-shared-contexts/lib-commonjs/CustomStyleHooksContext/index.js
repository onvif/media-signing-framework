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
    CustomStyleHooksContext: function() {
        return _CustomStyleHooksContext.CustomStyleHooksContext;
    },
    CustomStyleHooksProvider: function() {
        return _CustomStyleHooksContext.CustomStyleHooksProvider;
    },
    useCustomStyleHook: function() {
        return _CustomStyleHooksContext.useCustomStyleHook;
    }
});
const _CustomStyleHooksContext = require("./CustomStyleHooksContext");
