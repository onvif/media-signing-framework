import { assertSlots } from '@fluentui/react-utilities';
import { renderToggleButton_unstable } from '@fluentui/react-button';
/**
 * Render the final JSX of CarouselAutoplayButton
 */ export const renderCarouselAutoplayButton_unstable = (state)=>{
    assertSlots(state);
    // We render the underlying react-button with injected carousel functionality
    return renderToggleButton_unstable(state);
};
