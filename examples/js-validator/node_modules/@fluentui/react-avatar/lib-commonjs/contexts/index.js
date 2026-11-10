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
    AvatarContextProvider: function() {
        return _AvatarContext.AvatarContextProvider;
    },
    AvatarGroupContext: function() {
        return _AvatarGroupContext.AvatarGroupContext;
    },
    AvatarGroupProvider: function() {
        return _AvatarGroupContext.AvatarGroupProvider;
    },
    useAvatarContext: function() {
        return _AvatarContext.useAvatarContext;
    },
    useAvatarGroupContext_unstable: function() {
        return _AvatarGroupContext.useAvatarGroupContext_unstable;
    }
});
const _AvatarGroupContext = require("./AvatarGroupContext");
const _AvatarContext = require("./AvatarContext");
