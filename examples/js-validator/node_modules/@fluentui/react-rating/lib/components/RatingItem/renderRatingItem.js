  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of RatingItem
 */ export const renderRatingItem_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.halfValueInput && /*#__PURE__*/ _jsx(state.halfValueInput, {}),
            state.fullValueInput && /*#__PURE__*/ _jsx(state.fullValueInput, {}),
            state.unselectedIcon && /*#__PURE__*/ _jsx(state.unselectedIcon, {}),
            state.selectedIcon && /*#__PURE__*/ _jsx(state.selectedIcon, {})
        ]
    });
};
