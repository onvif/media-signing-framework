import { assertSlots } from '@fluentui/react-utilities';
import { renderButton_unstable } from '@fluentui/react-button';
/**
 * Render the final JSX of CarouselButton
 */ export const renderCarouselButton_unstable = (state)=>{
    assertSlots(state);
    // We render the underlying react-button with injected carousel functionality
    return renderButton_unstable(state);
};
