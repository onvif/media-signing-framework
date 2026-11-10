  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Function that renders the final JSX of the component
 */ export const renderAccordionPanel_unstable = (state)=>{
    assertSlots(state);
    return state.collapseMotion ? /*#__PURE__*/ _jsx(state.collapseMotion, {
        children: /*#__PURE__*/ _jsx(state.root, {})
    }) : /*#__PURE__*/ _jsx(state.root, {});
};
