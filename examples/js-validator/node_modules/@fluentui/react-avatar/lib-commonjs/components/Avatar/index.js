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
    Avatar: function() {
        return _Avatar.Avatar;
    },
    DEFAULT_STRINGS: function() {
        return _useAvatar.DEFAULT_STRINGS;
    },
    avatarClassNames: function() {
        return _useAvatarStylesstyles.avatarClassNames;
    },
    renderAvatar_unstable: function() {
        return _renderAvatar.renderAvatar_unstable;
    },
    useAvatarStyles_unstable: function() {
        return _useAvatarStylesstyles.useAvatarStyles_unstable;
    },
    useAvatar_unstable: function() {
        return _useAvatar.useAvatar_unstable;
    },
    useSizeStyles: function() {
        return _useAvatarStylesstyles.useSizeStyles;
    }
});
const _Avatar = require("./Avatar");
const _renderAvatar = require("./renderAvatar");
const _useAvatar = require("./useAvatar");
const _useAvatarStylesstyles = require("./useAvatarStyles.styles");
