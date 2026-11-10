  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { CarouselProvider } from './Carousel/CarouselContext';
/**
 * Render the final JSX of TeachingPopoverCarousel
 */ export const renderTeachingPopoverCarousel_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(CarouselProvider, {
        value: contextValues.carousel,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
