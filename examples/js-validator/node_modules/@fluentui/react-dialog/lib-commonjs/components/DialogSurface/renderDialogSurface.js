"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderDialogSurface_unstable", {
    enumerable: true,
    get: function() {
        return renderDialogSurface_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactportal = require("@fluentui/react-portal");
const _reactutilities = require("@fluentui/react-utilities");
const _contexts = require("../../contexts");
const renderDialogSurface_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(_reactportal.Portal, {
        mountNode: state.mountNode,
        children: [
            state.backdrop && // TODO: state.backdropMotion is non nullable, but assertSlots asserts it as nullable
            // FIXME: this should be resolved by properly splitting props and state slots declaration
            state.backdropMotion && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.backdropMotion, {
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.backdrop, {})
            }),
            /*#__PURE__*/ (0, _jsxruntime.jsx)(_contexts.DialogSurfaceProvider, {
                value: contextValues.dialogSurface,
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
            })
        ]
    });
};
