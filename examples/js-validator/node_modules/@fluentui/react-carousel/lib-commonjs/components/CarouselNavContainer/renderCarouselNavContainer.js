"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderCarouselNavContainer_unstable", {
    enumerable: true,
    get: function() {
        return renderCarouselNavContainer_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderCarouselNavContainer_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            !state.autoplayTooltip && state.autoplay && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.autoplay, {}),
            state.autoplayTooltip && state.autoplay && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.autoplayTooltip, {
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.autoplay, {})
            }),
            !state.prevTooltip && state.prev && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.prev, {}),
            state.prevTooltip && state.prev && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.prevTooltip, {
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.prev, {})
            }),
            state.root.children,
            !state.nextTooltip && state.next && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.next, {}),
            state.nextTooltip && state.next && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.nextTooltip, {
                children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.next, {})
            })
        ]
    });
};
