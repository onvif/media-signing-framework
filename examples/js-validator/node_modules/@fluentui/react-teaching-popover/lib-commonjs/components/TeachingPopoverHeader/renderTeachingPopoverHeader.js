"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverHeader_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverHeader_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTeachingPopoverHeader_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.icon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.icon, {}),
            state.root.children,
            state.dismissButton && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.dismissButton, {})
        ]
    });
};
