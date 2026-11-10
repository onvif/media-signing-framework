  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of CarouselNavContainer
 */ export const renderCarouselNavContainer_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            !state.autoplayTooltip && state.autoplay && /*#__PURE__*/ _jsx(state.autoplay, {}),
            state.autoplayTooltip && state.autoplay && /*#__PURE__*/ _jsx(state.autoplayTooltip, {
                children: /*#__PURE__*/ _jsx(state.autoplay, {})
            }),
            !state.prevTooltip && state.prev && /*#__PURE__*/ _jsx(state.prev, {}),
            state.prevTooltip && state.prev && /*#__PURE__*/ _jsx(state.prevTooltip, {
                children: /*#__PURE__*/ _jsx(state.prev, {})
            }),
            state.root.children,
            !state.nextTooltip && state.next && /*#__PURE__*/ _jsx(state.next, {}),
            state.nextTooltip && state.next && /*#__PURE__*/ _jsx(state.nextTooltip, {
                children: /*#__PURE__*/ _jsx(state.next, {})
            })
        ]
    });
};
