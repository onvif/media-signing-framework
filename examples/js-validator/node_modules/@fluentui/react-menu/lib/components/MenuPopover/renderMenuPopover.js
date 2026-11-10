  import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { Portal } from '@fluentui/react-portal';
/**
 * Render the final JSX of MenuPopover
 */ export const renderMenuPopover_unstable = (state)=>{
    assertSlots(state);
    if (state.inline) {
        return /*#__PURE__*/ _jsxs(_Fragment, {
            children: [
                /*#__PURE__*/ _jsx(state.root, {}),
                state.safeZone
            ]
        });
    }
    return /*#__PURE__*/ _jsxs(Portal, {
        mountNode: state.mountNode,
        children: [
            /*#__PURE__*/ _jsx(state.root, {}),
            state.safeZone
        ]
    });
};
