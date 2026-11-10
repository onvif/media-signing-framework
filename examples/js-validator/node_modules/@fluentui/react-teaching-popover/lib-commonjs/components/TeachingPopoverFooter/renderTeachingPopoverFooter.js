"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverFooter_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverFooter_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTeachingPopoverFooter_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            /*#__PURE__*/ (0, _jsxruntime.jsx)(state.primary, {}),
            state.secondary && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.secondary, {})
        ]
    });
};
