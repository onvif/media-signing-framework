"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderNavSubItemGroup_unstable", {
    enumerable: true,
    get: function() {
        return renderNavSubItemGroup_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderNavSubItemGroup_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return state.collapseMotion ? /*#__PURE__*/ (0, _jsxruntime.jsx)(state.collapseMotion, {
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
    }) : /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {});
};
