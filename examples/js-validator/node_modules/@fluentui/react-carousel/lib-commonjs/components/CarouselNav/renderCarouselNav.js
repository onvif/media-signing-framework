"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderCarouselNav_unstable", {
    enumerable: true,
    get: function() {
        return renderCarouselNav_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _CarouselNavContext = require("./CarouselNavContext");
const _CarouselNavIndexContext = require("./CarouselNavIndexContext");
const renderCarouselNav_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    const { totalSlides, renderNavButton } = state;
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(_CarouselNavContext.CarouselNavContextProvider, {
            value: contextValues.carouselNav,
            children: new Array(totalSlides).fill(null).map((_, index)=>/*#__PURE__*/ (0, _jsxruntime.jsx)(_CarouselNavIndexContext.CarouselNavIndexContextProvider, {
                    value: index,
                    children: renderNavButton(index)
                }, index))
        })
    });
};
