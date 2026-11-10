"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderPortal_unstable", {
    enumerable: true,
    get: function() {
        return renderPortal_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _reactdom = /*#__PURE__*/ _interop_require_wildcard._(require("react-dom"));
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const renderPortal_unstable = (state)=>{
    return /*#__PURE__*/ _react.createElement("span", {
        hidden: true,
        ref: state.virtualParentRootRef
    }, state.mountNode && /*#__PURE__*/ _reactdom.createPortal(/*#__PURE__*/ _react.createElement(_react.Fragment, null, state.children, /*#__PURE__*/ _react.createElement("span", {
        hidden: true
    })), state.mountNode));
};
