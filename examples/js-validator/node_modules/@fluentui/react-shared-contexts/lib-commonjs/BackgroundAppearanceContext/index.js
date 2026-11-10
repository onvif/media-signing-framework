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
    BackgroundAppearanceContext: function() {
        return _BackgroundAppearanceContext.BackgroundAppearanceContext;
    },
    BackgroundAppearanceProvider: function() {
        return _BackgroundAppearanceContext.BackgroundAppearanceProvider;
    },
    useBackgroundAppearance: function() {
        return _BackgroundAppearanceContext.useBackgroundAppearance;
    }
});
const _BackgroundAppearanceContext = require("./BackgroundAppearanceContext");
