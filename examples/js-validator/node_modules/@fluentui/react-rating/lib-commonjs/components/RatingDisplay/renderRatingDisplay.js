"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderRatingDisplay_unstable", {
    enumerable: true,
    get: function() {
        return renderRatingDisplay_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _RatingItemContext = require("../../contexts/RatingItemContext");
const renderRatingDisplay_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_RatingItemContext.RatingItemProvider, {
        value: contextValues.ratingItem,
        children: /*#__PURE__*/ (0, _jsxruntime.jsxs)(state.root, {
            children: [
                state.root.children,
                state.valueText && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.valueText, {}),
                state.countText && /*#__PURE__*/ (0, _jsxruntime.jsx)(state.countText, {})
            ]
        })
    });
};
