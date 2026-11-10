"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverCarouselFooter_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverCarouselFooter_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const renderTeachingPopoverCarouselFooter_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    const { layout } = state;
    return /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
        children: [
            layout === 'centered' && state.previous && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.previous, {}),
            state.root.children,
            layout === 'offset' && state.previous && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.previous, {}),
            /*#__PURE__*/ (0, _jsxruntime.jsx)(state.next, {})
        ]
    });
};
