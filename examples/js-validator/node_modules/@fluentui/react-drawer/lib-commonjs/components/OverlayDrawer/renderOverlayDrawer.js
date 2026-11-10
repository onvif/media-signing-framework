"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderOverlayDrawer_unstable", {
    enumerable: true,
    get: function() {
        return renderOverlayDrawer_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _drawerContext = require("../../contexts/drawerContext");
const renderOverlayDrawer_unstable = (state, contextValue)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_drawerContext.DrawerProvider, {
        value: contextValue,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.dialog, {
            children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
        })
    });
};
