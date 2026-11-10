  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { LinkContextProvider } from '@fluentui/react-link';
/**
 * Render the final JSX of MessageBarBody
 */ export const renderMessageBarBody_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(LinkContextProvider, {
        value: contextValues.link,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
