import { getIntrinsicElementProps, slot } from '@fluentui/react-utilities';
import * as React from 'react';
import { CarouselItem } from '../TeachingPopoverCarousel/Carousel/CarouselItem/Carouseltem';
/**
 * Returns the props and state required to render the component
 * @param props - TeachingPopoverCarouselCard properties
 * @param ref - reference to root HTMLElement of TeachingPopoverCarouselCard
 */ export const useTeachingPopoverCarouselCard_unstable = (props, ref)=>{
    const { value } = props;
    return {
        value,
        components: {
            root: CarouselItem
        },
        root: slot.always({
            ...getIntrinsicElementProps('div', {
                ref,
                ...props
            }),
            value
        }, {
            elementType: CarouselItem
        })
    };
};
