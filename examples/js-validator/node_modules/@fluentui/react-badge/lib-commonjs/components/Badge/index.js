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
    Badge: function() {
        return _Badge.Badge;
    },
    badgeClassNames: function() {
        return _useBadgeStylesstyles.badgeClassNames;
    },
    renderBadge_unstable: function() {
        return _renderBadge.renderBadge_unstable;
    },
    useBadgeStyles_unstable: function() {
        return _useBadgeStylesstyles.useBadgeStyles_unstable;
    },
    useBadge_unstable: function() {
        return _useBadge.useBadge_unstable;
    }
});
const _Badge = require("./Badge");
const _renderBadge = require("./renderBadge");
const _useBadge = require("./useBadge");
const _useBadgeStylesstyles = require("./useBadgeStyles.styles");
