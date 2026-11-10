"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useNavSectionHeader_unstable", {
    enumerable: true,
    get: function() {
        return useNavSectionHeader_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactutilities = require("@fluentui/react-utilities");
const useNavSectionHeader_unstable = (props, ref)=>{
    return {
        components: {
            root: 'h3'
        },
        root: _reactutilities.slot.always((0, _reactutilities.getIntrinsicElementProps)('h3', {
            ref,
            ...props
        }), {
            elementType: 'h3'
        })
    };
};
