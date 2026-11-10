  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { NavProvider } from '../NavContext';
export const renderNavDrawer_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(NavProvider, {
        value: contextValues.nav,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
