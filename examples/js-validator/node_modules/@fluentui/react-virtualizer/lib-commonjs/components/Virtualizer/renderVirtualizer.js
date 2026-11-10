"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    renderVirtualizerChildPlaceholder: function() {
        return renderVirtualizerChildPlaceholder;
    },
    renderVirtualizer_unstable: function() {
        return renderVirtualizer_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactutilities = require("@fluentui/react-utilities");
const renderVirtualizer_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(_react.Fragment, {
        children: [
            /*#__PURE__*/ (0, _jsxruntime.jsx)(state.beforeContainer, {
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.before, {})
            }),
            state.virtualizedChildren,
            /*#__PURE__*/ (0, _jsxruntime.jsx)(state.afterContainer, {
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.after, {})
            })
        ]
    });
};
const renderVirtualizerChildPlaceholder = (child, index)=>{
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_react.Suspense, {
        fallback: null,
        children: child
    }, `fui-virtualizer-placeholder-${index}`);
};
