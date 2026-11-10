"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderNavCategory_unstable", {
    enumerable: true,
    get: function() {
        return renderNavCategory_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _NavCategoryContext = require("../NavCategoryContext");
const renderNavCategory_unstable = (state, contextValues)=>{
    return /*#__PURE__*/ _react.createElement(_NavCategoryContext.NavCategoryProvider, {
        value: contextValues.categoryValue
    }, state.children);
};
