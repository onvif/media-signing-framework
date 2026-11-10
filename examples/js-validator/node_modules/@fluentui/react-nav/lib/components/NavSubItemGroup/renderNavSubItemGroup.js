  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of NavSubItemGroup
 */ export const renderNavSubItemGroup_unstable = (state)=>{
    assertSlots(state);
    return state.collapseMotion ? /*#__PURE__*/ _jsx(state.collapseMotion, {
        children: /*#__PURE__*/ _jsx(state.root, {})
    }) : /*#__PURE__*/ _jsx(state.root, {});
};
