  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import * as React from 'react';
import { assertSlots } from '@fluentui/react-utilities';
/**
 * @internal
 *
 * Helper function to render button slots
 */ const renderButtonSlot = (Button, ButtonTooltip)=>{
    if (!Button) {
        return null;
    }
    if (ButtonTooltip) {
        return /*#__PURE__*/ _jsx(ButtonTooltip, {
            children: /*#__PURE__*/ _jsx(Button, {})
        });
    }
    return /*#__PURE__*/ _jsx(Button, {});
};
/**
 * Render the final JSX of SplitNavItem
 */ export const renderSplitNavItem_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(state.root, {
        children: [
            state.navItem && /*#__PURE__*/ _jsx(state.navItem, {}),
            renderButtonSlot(state.actionButton, state.actionButtonTooltip),
            renderButtonSlot(state.menuButton, state.menuButtonTooltip),
            renderButtonSlot(state.toggleButton, state.toggleButtonTooltip)
        ]
    });
};
