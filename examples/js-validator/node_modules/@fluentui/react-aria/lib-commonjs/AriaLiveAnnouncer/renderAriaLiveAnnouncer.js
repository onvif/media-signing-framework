"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderAriaLiveAnnouncer_unstable", {
    enumerable: true,
    get: function() {
        return renderAriaLiveAnnouncer_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactsharedcontexts = require("@fluentui/react-shared-contexts");
const renderAriaLiveAnnouncer_unstable = (state, contextValues)=>{
    return /*#__PURE__*/ _react.createElement(_reactsharedcontexts.AnnounceProvider, {
        value: contextValues.announce
    }, state.children);
};
