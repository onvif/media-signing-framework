  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { CarouselNavContextProvider } from './CarouselNavContext';
import { CarouselNavIndexContextProvider } from './CarouselNavIndexContext';
/**
 * Render the final JSX of CarouselNav
 */ export const renderCarouselNav_unstable = (state, contextValues)=>{
    assertSlots(state);
    const { totalSlides, renderNavButton } = state;
    return /*#__PURE__*/ _jsx(state.root, {
        children: /*#__PURE__*/ _jsx(CarouselNavContextProvider, {
            value: contextValues.carouselNav,
            children: new Array(totalSlides).fill(null).map((_, index)=>/*#__PURE__*/ _jsx(CarouselNavIndexContextProvider, {
                    value: index,
                    children: renderNavButton(index)
                }, index))
        })
    });
};
