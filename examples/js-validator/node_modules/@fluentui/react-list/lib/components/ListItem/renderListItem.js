  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of ListItem
 */ export const renderListItem_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.checkmark && /*#__PURE__*/ _jsx(state.checkmark, {}),
            state.root.children
        ]
    });
};
