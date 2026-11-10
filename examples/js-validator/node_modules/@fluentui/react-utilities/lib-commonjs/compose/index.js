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
    SLOT_CLASS_NAME_PROP_SYMBOL: function() {
        return _constants.SLOT_CLASS_NAME_PROP_SYMBOL;
    },
    SLOT_ELEMENT_TYPE_SYMBOL: function() {
        return _constants.SLOT_ELEMENT_TYPE_SYMBOL;
    },
    SLOT_RENDER_FUNCTION_SYMBOL: function() {
        return _constants.SLOT_RENDER_FUNCTION_SYMBOL;
    },
    assertSlots: function() {
        return _assertSlots.assertSlots;
    },
    getIntrinsicElementProps: function() {
        return _getIntrinsicElementProps.getIntrinsicElementProps;
    },
    getSlotClassNameProp_unstable: function() {
        return _getSlotClassNameProp.getSlotClassNameProp;
    },
    getSlots: function() {
        return _getSlots.getSlots;
    },
    getSlotsNext: function() {
        return _getSlotsNext.getSlotsNext;
    },
    isResolvedShorthand: function() {
        return _isResolvedShorthand.isResolvedShorthand;
    },
    isSlot: function() {
        return _isSlot.isSlot;
    },
    resolveShorthand: function() {
        return _resolveShorthand.resolveShorthand;
    },
    slot: function() {
        return _slot;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _slot = /*#__PURE__*/ _interop_require_wildcard._(require("./slot"));
const _isResolvedShorthand = require("./isResolvedShorthand");
const _constants = require("./constants");
const _isSlot = require("./isSlot");
const _assertSlots = require("./assertSlots");
const _getIntrinsicElementProps = require("./getIntrinsicElementProps");
const _getSlotClassNameProp = require("./getSlotClassNameProp");
const _getSlots = require("./deprecated/getSlots");
const _resolveShorthand = require("./deprecated/resolveShorthand");
const _getSlotsNext = require("./deprecated/getSlotsNext");
