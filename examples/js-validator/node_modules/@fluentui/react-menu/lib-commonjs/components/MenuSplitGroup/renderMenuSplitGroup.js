"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderMenuSplitGroup_unstable", {
    enumerable: true,
    get: function() {
        return renderMenuSplitGroup_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _menuSplitGroupContext = require("../../contexts/menuSplitGroupContext");
const renderMenuSplitGroup_unstable = (state, contexts)=>{
    (0, _reactutilities.assertSlots)(state);
    var _contexts_menuSplitGroup;
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_menuSplitGroupContext.MenuSplitGroupContextProvider, {
        value: (_contexts_menuSplitGroup = contexts === null || contexts === void 0 ? void 0 : contexts.menuSplitGroup) !== null && _contexts_menuSplitGroup !== void 0 ? _contexts_menuSplitGroup : _menuSplitGroupContext.menuSplitGroupContextDefaultValue,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
    });
};
