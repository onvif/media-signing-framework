  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Function that renders the final JSX of the component
 */ export const renderMenuItemSwitch_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.icon && /*#__PURE__*/ _jsx(state.icon, {}),
            state.content && /*#__PURE__*/ _jsxs(state.content, {
                children: [
                    state.content.children,
                    state.subText && /*#__PURE__*/ _jsx(state.subText, {})
                ]
            }),
            state.secondaryContent && /*#__PURE__*/ _jsx(state.secondaryContent, {}),
            state.switchIndicator && /*#__PURE__*/ _jsx(state.switchIndicator, {})
        ]
    });
};
