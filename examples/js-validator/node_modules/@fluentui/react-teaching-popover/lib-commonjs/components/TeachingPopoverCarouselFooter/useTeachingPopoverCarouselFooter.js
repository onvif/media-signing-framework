"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useTeachingPopoverCarouselFooter_unstable", {
    enumerable: true,
    get: function() {
        return useTeachingPopoverCarouselFooter_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _reactutilities = require("@fluentui/react-utilities");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _TeachingPopoverCarouselFooterButton = require("../TeachingPopoverCarouselFooterButton/TeachingPopoverCarouselFooterButton");
const useTeachingPopoverCarouselFooter_unstable = (props, ref)=>{
    const { layout = 'centered', initialStepText, finalStepText } = props;
    const previous = _reactutilities.slot.optional(props.previous, {
        defaultProps: {
            navType: 'prev',
            altText: initialStepText
        },
        renderByDefault: true,
        elementType: _TeachingPopoverCarouselFooterButton.TeachingPopoverCarouselFooterButton
    });
    const next = _reactutilities.slot.always(props.next, {
        defaultProps: {
            navType: 'next',
            altText: finalStepText
        },
        elementType: _TeachingPopoverCarouselFooterButton.TeachingPopoverCarouselFooterButton
    });
    return {
        layout,
        components: {
            root: 'div',
            next: _TeachingPopoverCarouselFooterButton.TeachingPopoverCarouselFooterButton,
            previous: _TeachingPopoverCarouselFooterButton.TeachingPopoverCarouselFooterButton
        },
        root: _reactutilities.slot.always((0, _reactutilities.getIntrinsicElementProps)('div', {
            ref,
            ...props
        }), {
            elementType: 'div'
        }),
        previous,
        next
    };
};
