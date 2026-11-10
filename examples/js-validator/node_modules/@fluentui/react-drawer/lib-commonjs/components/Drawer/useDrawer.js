"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useDrawer_unstable", {
    enumerable: true,
    get: function() {
        return useDrawer_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactutilities = require("@fluentui/react-utilities");
const _OverlayDrawer = require("../OverlayDrawer");
const _InlineDrawer = require("../InlineDrawer");
const useDrawer_unstable = (props, ref)=>{
    // casting here to convert a union of functions to a single function with the union of parameters
    const elementType = props.type === 'inline' ? _InlineDrawer.InlineDrawer : _OverlayDrawer.OverlayDrawer;
    const root = _reactutilities.slot.always({
        ref,
        ...props
    }, {
        elementType
    });
    return {
        components: {
            root: elementType
        },
        root
    };
};
