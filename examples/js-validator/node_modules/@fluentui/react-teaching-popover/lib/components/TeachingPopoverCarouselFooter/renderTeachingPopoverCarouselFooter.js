  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of TeachingPopoverCarouselFooter
 */ export const renderTeachingPopoverCarouselFooter_unstable = (state)=>{
    assertSlots(state);
    const { layout } = state;
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            layout === 'centered' && state.previous && /*#__PURE__*/ _jsx(state.previous, {}),
            state.root.children,
            layout === 'offset' && state.previous && /*#__PURE__*/ _jsx(state.previous, {}),
            /*#__PURE__*/ _jsx(state.next, {})
        ]
    });
};
