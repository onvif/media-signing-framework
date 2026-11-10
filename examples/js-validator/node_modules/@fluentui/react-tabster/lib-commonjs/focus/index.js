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
    applyFocusVisiblePolyfill: function() {
        return _focusVisiblePolyfill.applyFocusVisiblePolyfill;
    },
    applyFocusWithinPolyfill: function() {
        return _focusWithinPolyfill.applyFocusWithinPolyfill;
    },
    createCustomFocusIndicatorStyle: function() {
        return _createCustomFocusIndicatorStyle.createCustomFocusIndicatorStyle;
    },
    createFocusOutlineStyle: function() {
        return _createFocusOutlineStyle.createFocusOutlineStyle;
    }
});
const _createCustomFocusIndicatorStyle = require("./createCustomFocusIndicatorStyle");
const _createFocusOutlineStyle = require("./createFocusOutlineStyle");
const _focusVisiblePolyfill = require("./focusVisiblePolyfill");
const _focusWithinPolyfill = require("./focusWithinPolyfill");
