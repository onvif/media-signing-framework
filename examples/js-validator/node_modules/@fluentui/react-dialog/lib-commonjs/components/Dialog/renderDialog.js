"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderDialog_unstable", {
    enumerable: true,
    get: function() {
        return renderDialog_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _MotionRefForwarder = require("../MotionRefForwarder");
const _contexts = require("../../contexts");
const renderDialog_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_contexts.DialogProvider, {
        value: contextValues.dialog,
        children: /*#__PURE__*/ (0, _jsxruntime.jsxs)(_contexts.DialogSurfaceProvider, {
            value: contextValues.dialogSurface,
            children: [
                state.trigger,
                state.content && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.surfaceMotion, {
                    children: /*#__PURE__*/ (0, _jsxruntime.jsx)(_MotionRefForwarder.MotionRefForwarder, {
                        children: state.content
                    })
                })
            ]
        })
    });
};
