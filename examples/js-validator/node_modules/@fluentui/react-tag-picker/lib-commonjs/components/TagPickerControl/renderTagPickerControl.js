"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTagPickerControl_unstable", {
    enumerable: true,
    get: function() {
        return renderTagPickerControl_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTagPickerControl_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.root.children,
            state.aside && /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.aside, {
                children: [
                    state.secondaryAction && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.secondaryAction, {}),
                    state.expandIcon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.expandIcon, {})
                ]
            })
        ]
    });
};
