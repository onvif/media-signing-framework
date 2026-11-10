  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { CarouselSliderContextProvider } from '../CarouselSlider/CarouselSliderContext';
/**
 * Render the final JSX of CarouselViewport
 */ export const renderCarouselViewport_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(CarouselSliderContextProvider, {
        value: contextValues.carouselSlider,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
