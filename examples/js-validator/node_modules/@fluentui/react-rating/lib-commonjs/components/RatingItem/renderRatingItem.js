"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderRatingItem_unstable", {
    enumerable: true,
    get: function() {
        return renderRatingItem_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderRatingItem_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.halfValueInput && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.halfValueInput, {}),
            state.fullValueInput && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.fullValueInput, {}),
            state.unselectedIcon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.unselectedIcon, {}),
            state.selectedIcon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.selectedIcon, {})
        ]
    });
};
