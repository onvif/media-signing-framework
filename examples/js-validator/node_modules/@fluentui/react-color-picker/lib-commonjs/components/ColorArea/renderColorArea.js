"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderColorArea_unstable", {
    enumerable: true,
    get: function() {
        return renderColorArea_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderColorArea_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {
        children: /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.thumb, {
            children: [
                /*#__PURE__*/ (0, _jsxruntime.jsx)(state.inputX, {}),
                /*#__PURE__*/ (0, _jsxruntime.jsx)(state.inputY, {})
            ]
        })
    });
};
