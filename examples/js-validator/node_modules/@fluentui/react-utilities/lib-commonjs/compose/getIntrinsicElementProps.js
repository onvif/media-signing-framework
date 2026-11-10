"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getIntrinsicElementProps", {
    enumerable: true,
    get: function() {
        return getIntrinsicElementProps;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _getNativeElementProps = require("../utils/getNativeElementProps");
const getIntrinsicElementProps = (tagName, // eslint-disable-next-line @typescript-eslint/no-restricted-types -- in order to not introduce Type Restriction CHANGe which is kinda "breaking change from Types POV", we don't enforce our custom `RefAttributes` in this API, to be compatible with scenarios where non v9 interfaces might be used. This may/will change with React 19
props, excludedPropNames)=>{
    var _props_as;
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return (0, _getNativeElementProps.getNativeElementProps)((_props_as = props.as) !== null && _props_as !== void 0 ? _props_as : tagName, props, excludedPropNames);
};
