  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of PickerControl
 */ export const renderTagPickerControl_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.root.children,
            state.aside && /*#__PURE__*/ _jsxs(state.aside, {
                children: [
                    state.secondaryAction && /*#__PURE__*/ _jsx(state.secondaryAction, {}),
                    state.expandIcon && /*#__PURE__*/ _jsx(state.expandIcon, {})
                ]
            })
        ]
    });
};
