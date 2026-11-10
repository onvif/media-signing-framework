"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderList_unstable", {
    enumerable: true,
    get: function() {
        return renderList_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _listContext = require("./listContext");
const renderList_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_listContext.ListContextProvider, {
        value: contextValues.listContext,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(_listContext.ListSynchronousContextProvider, {
            value: contextValues.synchronousContext,
            children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
        })
    });
};
