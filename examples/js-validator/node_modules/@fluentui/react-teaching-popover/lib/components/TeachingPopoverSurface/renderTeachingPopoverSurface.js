import { assertSlots } from '@fluentui/react-utilities';
import { renderPopoverSurface_unstable } from '@fluentui/react-popover';
/**
 * Render the final JSX of PopoverSurface
 */ export const renderTeachingPopoverSurface_unstable = (state)=>{
    assertSlots(state);
    // For now we are just extending the base surface
    return renderPopoverSurface_unstable(state);
};
