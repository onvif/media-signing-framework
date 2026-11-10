"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "isResolvedShorthand", {
    enumerable: true,
    get: function() {
        return isResolvedShorthand;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
function isResolvedShorthand(shorthand) {
    return shorthand !== null && typeof shorthand === 'object' && !Array.isArray(shorthand) && !_react.isValidElement(shorthand);
}
