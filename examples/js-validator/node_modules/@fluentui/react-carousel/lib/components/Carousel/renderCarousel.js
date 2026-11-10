  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { CarouselProvider } from '../CarouselContext';
/**
 * Render the final JSX of Carousel
 */ export const renderCarousel_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(CarouselProvider, {
        value: contextValues.carousel,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
