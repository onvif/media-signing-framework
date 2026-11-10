"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderMessageBarActions_unstable", {
    enumerable: true,
    get: function() {
        return renderMessageBarActions_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _reactbutton = require("@fluentui/react-button");
const renderMessageBarActions_unstable = (state, contexts)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(_reactbutton.ButtonContextProvider, {
        value: contexts.button,
        children: [
            state.layout === 'multiline' && state.containerAction && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.containerAction, {}, "containerAction"),
            /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {}),
            state.layout !== 'multiline' && state.containerAction && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.containerAction, {}, "containerAction")
        ]
    });
};
