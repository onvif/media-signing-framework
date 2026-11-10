"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderNav_unstable", {
    enumerable: true,
    get: function() {
        return renderNav_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _NavContext = require("../NavContext");
const renderNav_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_NavContext.NavProvider, {
        value: contextValues.nav,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
    });
};
