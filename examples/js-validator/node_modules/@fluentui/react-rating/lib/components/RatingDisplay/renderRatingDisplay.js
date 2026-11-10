  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { RatingItemProvider } from '../../contexts/RatingItemContext';
/**
 * Render the final JSX of RatingDisplay
 */ export const renderRatingDisplay_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(RatingItemProvider, {
        value: contextValues.ratingItem,
        children: /*#__PURE__*/ _jsxs(state.root, {
            children: [
                state.root.children,
                state.valueText && /*#__PURE__*/ _jsx(state.valueText, {}),
                state.countText && /*#__PURE__*/ _jsx(state.countText, {})
            ]
        })
    });
};
