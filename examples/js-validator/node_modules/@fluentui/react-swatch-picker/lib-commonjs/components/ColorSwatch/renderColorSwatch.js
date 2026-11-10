"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderColorSwatch_unstable", {
    enumerable: true,
    get: function() {
        return renderColorSwatch_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderColorSwatch_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.root.children,
            state.icon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.icon, {}),
            state.disabled && state.disabledIcon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.disabledIcon, {})
        ]
    });
};
