"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderCarouselSlider_unstable", {
    enumerable: true,
    get: function() {
        return renderCarouselSlider_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _CarouselSliderContext = require("./CarouselSliderContext");
const renderCarouselSlider_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_CarouselSliderContext.CarouselSliderContextProvider, {
        value: contextValues.carouselSlider,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {})
    });
};
