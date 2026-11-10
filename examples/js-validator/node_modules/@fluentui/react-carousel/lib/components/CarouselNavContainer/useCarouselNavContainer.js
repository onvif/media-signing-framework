import * as React from 'react';
import { getIntrinsicElementProps, slot } from '@fluentui/react-utilities';
import { CarouselAutoplayButton } from '../CarouselAutoplayButton/CarouselAutoplayButton';
import { CarouselButton } from '../CarouselButton/CarouselButton';
import { Tooltip } from '@fluentui/react-tooltip';
/**
 * Create the state required to render CarouselNavContainer.
 *
 * The returned state can be modified with hooks such as useCarouselNavContainerStyles_unstable,
 * before being passed to renderCarouselNavContainer_unstable.
 *
 * @param props - props from this instance of CarouselNavContainer
 * @param ref - reference to root HTMLDivElement of CarouselNavContainer
 */ export const useCarouselNavContainer_unstable = (props, ref)=>{
    const { layout } = props;
    const next = slot.optional(props.next, {
        defaultProps: {
            navType: 'next'
        },
        elementType: CarouselButton,
        renderByDefault: true
    });
    const prev = slot.optional(props.prev, {
        defaultProps: {
            navType: 'prev'
        },
        elementType: CarouselButton,
        renderByDefault: true
    });
    const autoplay = slot.optional(props.autoplay, {
        elementType: CarouselAutoplayButton,
        renderByDefault: !!props.autoplay || !!props.autoplayTooltip
    });
    const nextTooltip = slot.optional(props.nextTooltip, {
        defaultProps: {},
        elementType: Tooltip,
        renderByDefault: false
    });
    const prevTooltip = slot.optional(props.prevTooltip, {
        defaultProps: {},
        elementType: Tooltip,
        renderByDefault: false
    });
    const autoplayTooltip = slot.optional(props.autoplayTooltip, {
        defaultProps: {},
        elementType: Tooltip,
        renderByDefault: false
    });
    return {
        layout,
        components: {
            root: 'div',
            next: CarouselButton,
            prev: CarouselButton,
            autoplay: CarouselAutoplayButton,
            nextTooltip: Tooltip,
            prevTooltip: Tooltip,
            autoplayTooltip: Tooltip
        },
        root: slot.always(getIntrinsicElementProps('div', {
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
