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
    ButtonContextProvider: function() {
        return _ButtonContext.ButtonContextProvider;
    },
    useButtonContext: function() {
        return _ButtonContext.useButtonContext;
    }
});
const _ButtonContext = require("./ButtonContext");
