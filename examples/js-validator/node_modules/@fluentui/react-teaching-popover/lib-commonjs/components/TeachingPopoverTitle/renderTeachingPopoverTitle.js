"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverTitle_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverTitle_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTeachingPopoverTitle_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.root.children,
            state.dismissButton && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.dismissButton, {})
        ]
    });
};
