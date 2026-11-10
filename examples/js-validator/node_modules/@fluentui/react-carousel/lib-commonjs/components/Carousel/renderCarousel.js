"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderCarousel_unstable", {
    enumerable: true,
    get: function() {
        return renderCarousel_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _CarouselContext = require("../CarouselContext");
const renderCarousel_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_CarouselContext.CarouselProvider, {
        value: contextValues.carousel,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
    });
};
