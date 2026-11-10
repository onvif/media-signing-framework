  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of TeachingPopoverHeader
 */ export const renderTeachingPopoverHeader_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.icon && /*#__PURE__*/ _jsx(state.icon, {}),
            state.root.children,
            state.dismissButton && /*#__PURE__*/ _jsx(state.dismissButton, {})
        ]
    });
};
