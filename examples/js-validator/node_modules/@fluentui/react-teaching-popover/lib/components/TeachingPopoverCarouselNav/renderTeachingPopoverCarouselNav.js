  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { ValueIdContextProvider } from './valueIdContext';
/**
 * Render the final JSX of TeachingPopoverCarouselNav
 */ export const renderTeachingPopoverCarouselNav_unstable = (state)=>{
    assertSlots(state);
    const { values, renderNavButton } = state;
    return /*#__PURE__*/ _jsx(state.root, {
        children: values.map((value)=>/*#__PURE__*/ _jsx(ValueIdContextProvider, {
                value: value,
                children: renderNavButton(value)
            }, value))
    });
};
