"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useTeachingPopoverCarouselCard_unstable", {
    enumerable: true,
    get: function() {
        return useTeachingPopoverCarouselCard_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _reactutilities = require("@fluentui/react-utilities");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _Carouseltem = require("../TeachingPopoverCarousel/Carousel/CarouselItem/Carouseltem");
const useTeachingPopoverCarouselCard_unstable = (props, ref)=>{
    const { value } = props;
    return {
        value,
        components: {
            root: _Carouseltem.CarouselItem
        },
        root: _reactutilities.slot.always({
            ...(0, _reactutilities.getIntrinsicElementProps)('div', {
                ref,
                ...props
            }),
            value
        }, {
            elementType: _Carouseltem.CarouselItem
        })
    };
};
