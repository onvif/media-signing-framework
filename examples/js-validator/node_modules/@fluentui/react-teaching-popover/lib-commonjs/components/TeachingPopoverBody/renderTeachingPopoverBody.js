"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverBody_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverBody_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTeachingPopoverBody_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.media && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.media, {}),
            state.root.children
        ]
    });
};
