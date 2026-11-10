"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderRating_unstable", {
    enumerable: true,
    get: function() {
        return renderRating_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _RatingItemContext = require("../../contexts/RatingItemContext");
const renderRating_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_RatingItemContext.RatingItemProvider, {
        value: contextValues.ratingItem,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
    });
};
