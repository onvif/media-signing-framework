"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderMenuItemSwitch_unstable", {
    enumerable: true,
    get: function() {
        return renderMenuItemSwitch_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderMenuItemSwitch_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            state.icon && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.icon, {}),
            state.content && /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.content, {
                children: [
                    state.content.children,
                    state.subText && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.subText, {})
                ]
            }),
            state.secondaryContent && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.secondaryContent, {}),
            state.switchIndicator && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.switchIndicator, {})
        ]
    });
};
