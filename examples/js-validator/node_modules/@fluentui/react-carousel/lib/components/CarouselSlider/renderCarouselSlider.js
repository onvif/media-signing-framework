  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { CarouselSliderContextProvider } from './CarouselSliderContext';
/**
 * Render the final JSX of CarouselSlider
 */ export const renderCarouselSlider_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(CarouselSliderContextProvider, {
        value: contextValues.carouselSlider,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
