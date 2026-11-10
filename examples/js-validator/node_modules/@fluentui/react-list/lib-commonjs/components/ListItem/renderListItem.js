"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderListItem_unstable", {
    enumerable: true,
    get: function() {
        return renderListItem_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderListItem_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.checkmark && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.checkmark, {}),
            state.root.children
        ]
    });
};
