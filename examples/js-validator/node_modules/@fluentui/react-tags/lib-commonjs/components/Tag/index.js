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
    Tag: function() {
        return _Tag.Tag;
    },
    renderTag_unstable: function() {
        return _renderTag.renderTag_unstable;
    },
    tagClassNames: function() {
        return _useTagStylesstyles.tagClassNames;
    },
    useIconStyles: function() {
        return _useTagStylesstyles.useIconStyles;
    },
    useMediaStyles: function() {
        return _useTagStylesstyles.useMediaStyles;
    },
    usePrimaryTextStyles: function() {
        return _useTagStylesstyles.usePrimaryTextStyles;
    },
    useSecondaryTextBaseClassName: function() {
        return _useTagStylesstyles.useSecondaryTextBaseClassName;
    },
    useTagStyles_unstable: function() {
        return _useTagStylesstyles.useTagStyles_unstable;
    },
    useTag_unstable: function() {
        return _useTag.useTag_unstable;
    }
});
const _Tag = require("./Tag");
const _renderTag = require("./renderTag");
const _useTag = require("./useTag");
const _useTagStylesstyles = require("./useTagStyles.styles");
