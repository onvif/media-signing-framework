"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderNavCategoryItem_unstable", {
    enumerable: true,
    get: function() {
        return renderNavCategoryItem_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _NavCategoryItemContext = require("../NavCategoryItemContext");
const getExpandIcon = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    if (!state.expandIcon) {
        return null;
    }
    if (!state.expandIconMotion) {
        return /*#__PURE__*/ (0, _jsxruntime.jsx)(state.expandIcon, {});
    }
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(state.expandIconMotion, {
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.expandIcon, {})
    });
};
const renderNavCategoryItem_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_NavCategoryItemContext.NavCategoryItemProvider, {
        value: contextValues.navCategoryItem,
        children: /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
            children: [
                state.icon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.icon, {}),
                state.root.children,
                getExpandIcon(state)
            ]
        })
    });
};
