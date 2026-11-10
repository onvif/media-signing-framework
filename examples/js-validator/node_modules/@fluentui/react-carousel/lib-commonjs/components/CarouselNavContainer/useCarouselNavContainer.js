"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useCarouselNavContainer_unstable", {
    enumerable: true,
    get: function() {
        return useCarouselNavContainer_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactutilities = require("@fluentui/react-utilities");
const _CarouselAutoplayButton = require("../CarouselAutoplayButton/CarouselAutoplayButton");
const _CarouselButton = require("../CarouselButton/CarouselButton");
const _reacttooltip = require("@fluentui/react-tooltip");
const useCarouselNavContainer_unstable = (props, ref)=>{
    const { layout } = props;
    const next = _reactutilities.slot.optional(props.next, {
        defaultProps: {
            navType: 'next'
        },
        elementType: _CarouselButton.CarouselButton,
        renderByDefault: true
    });
    const prev = _reactutilities.slot.optional(props.prev, {
        defaultProps: {
            navType: 'prev'
        },
        elementType: _CarouselButton.CarouselButton,
        renderByDefault: true
    });
    const autoplay = _reactutilities.slot.optional(props.autoplay, {
        elementType: _CarouselAutoplayButton.CarouselAutoplayButton,
        renderByDefault: !!props.autoplay || !!props.autoplayTooltip
    });
    const nextTooltip = _reactutilities.slot.optional(props.nextTooltip, {
        defaultProps: {},
        elementType: _reacttooltip.Tooltip,
        renderByDefault: false
    });
    const prevTooltip = _reactutilities.slot.optional(props.prevTooltip, {
        defaultProps: {},
        elementType: _reacttooltip.Tooltip,
        renderByDefault: false
    });
    const autoplayTooltip = _reactutilities.slot.optional(props.autoplayTooltip, {
        defaultProps: {},
        elementType: _reacttooltip.Tooltip,
        renderByDefault: false
    });
    return {
        layout,
        components: {
            root: 'div',
            next: _CarouselButton.CarouselButton,
            prev: _CarouselButton.CarouselButton,
            autoplay: _CarouselAutoplayButton.CarouselAutoplayButton,
            nextTooltip: _reacttooltip.Tooltip,
            prevTooltip: _reacttooltip.Tooltip,
            autoplayTooltip: _reacttooltip.Tooltip
        },
        root: _reactutilities.slot.always((0, _reactutilities.getIntrinsicElementProps)('div', {
            ref,
            ...props
        }), {
            elementType: 'div'
        }),
        next,
        prev,
        autoplay,
        nextTooltip,
        prevTooltip,
        autoplayTooltip
    };
};
