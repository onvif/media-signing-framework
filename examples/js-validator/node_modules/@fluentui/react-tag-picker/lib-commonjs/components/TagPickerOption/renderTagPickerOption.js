"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTagPickerOption_unstable", {
    enumerable: true,
    get: function() {
        return renderTagPickerOption_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTagPickerOption_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.media && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.media, {}),
            state.root.children,
            state.secondaryContent && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.secondaryContent, {})
        ]
    });
};
