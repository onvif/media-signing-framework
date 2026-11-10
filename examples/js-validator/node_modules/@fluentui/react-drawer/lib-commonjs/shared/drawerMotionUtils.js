"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "mergePresenceSlots", {
    enumerable: true,
    get: function() {
        return mergePresenceSlots;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
function mergePresenceSlots(inputSlot, Component, params) {
    if (inputSlot === null) {
        return null;
    }
    return {
        ...inputSlot,
        children: (_, props)=>{
            if (inputSlot === null || inputSlot === void 0 ? void 0 : inputSlot.children) {
                return inputSlot.children(Component, {
                    ...props,
                    ...params
                });
            }
            return /*#__PURE__*/ _react.createElement(Component, {
                ...props,
                ...params
            }, props.children);
        }
    };
}
