"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderInlineDrawer_unstable", {
    enumerable: true,
    get: function() {
        return renderInlineDrawer_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _drawerContext = require("../../contexts/drawerContext");
const renderInlineDrawer_unstable = (state, contextValue)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_drawerContext.DrawerProvider, {
        value: contextValue,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.surfaceMotion, {
            children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
        })
    });
};
