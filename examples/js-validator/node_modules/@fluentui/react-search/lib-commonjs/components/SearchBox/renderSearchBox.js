"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderSearchBox_unstable", {
    enumerable: true,
    get: function() {
        return renderSearchBox_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderSearchBox_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.contentBefore && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.contentBefore, {}),
            /*#__PURE__*/ (0, _jsxruntime.jsx)(state.input, {}),
            state.contentAfter && /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.contentAfter, {
                children: [
                    state.contentAfter.children,
                    state.dismiss && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.dismiss, {})
                ]
            })
        ]
    });
};
