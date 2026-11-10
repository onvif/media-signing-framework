  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { RatingItemProvider } from '../../contexts/RatingItemContext';
/**
 * Render the final JSX of Rating
 */ export const renderRating_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(RatingItemProvider, {
        value: contextValues.ratingItem,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
