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
    ThemeClassNameProvider: function() {
        return _ThemeClassNameContext.ThemeClassNameProvider;
    },
    useThemeClassName: function() {
        return _ThemeClassNameContext.useThemeClassName;
    }
});
const _ThemeClassNameContext = require("./ThemeClassNameContext");
