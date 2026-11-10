"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getTriggerChild", {
    enumerable: true,
    get: function() {
        return getTriggerChild;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _isFluentTrigger = require("./isFluentTrigger");
function getTriggerChild(children) {
    if (!_react.isValidElement(children)) {
        return null;
    }
    return (0, _isFluentTrigger.isFluentTrigger)(children) ? getTriggerChild(// FIXME: This casting should be unnecessary as isFluentTrigger is a guard type method,
    // but for some reason it's failing on build
    children.props.children) : children;
}
