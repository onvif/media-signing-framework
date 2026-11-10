"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderSplitNavItem_unstable", {
    enumerable: true,
    get: function() {
        return renderSplitNavItem_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactutilities = require("@fluentui/react-utilities");
/**
 * @internal
 *
 * Helper function to render button slots
 */ const renderButtonSlot = (Button, ButtonTooltip)=>{
    if (!Button) {
        return null;
    }
    if (ButtonTooltip) {
        return /*#__PURE__*/ (0, _jsxruntime.jsx)(ButtonTooltip, {
            children: /*#__PURE__*/ (0, _jsxruntime.jsx)(Button, {})
        });
    }
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(Button, {});
};
const renderSplitNavItem_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.navItem && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.navItem, {}),
            renderButtonSlot(state.actionButton, state.actionButtonTooltip),
            renderButtonSlot(state.menuButton, state.menuButtonTooltip),
            renderButtonSlot(state.toggleButton, state.toggleButtonTooltip)
        ]
    });
};
