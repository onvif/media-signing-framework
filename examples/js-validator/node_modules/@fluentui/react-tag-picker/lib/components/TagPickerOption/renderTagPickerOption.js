  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of TagPickerOption
 */ export const renderTagPickerOption_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.media && /*#__PURE__*/ _jsx(state.media, {}),
            state.root.children,
            state.secondaryContent && /*#__PURE__*/ _jsx(state.secondaryContent, {})
        ]
    });
};
