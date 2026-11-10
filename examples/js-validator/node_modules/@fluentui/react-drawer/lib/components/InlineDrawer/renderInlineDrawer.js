  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { DrawerProvider } from '../../contexts/drawerContext';
/**
 * Render the final JSX of InlineDrawer
 */ export const renderInlineDrawer_unstable = (state, contextValue)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(DrawerProvider, {
        value: contextValue,
        children: /*#__PURE__*/ _jsx(state.surfaceMotion, {
            children: /*#__PURE__*/ _jsx(state.root, {})
        })
    });
};
