  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { ButtonContextProvider } from '@fluentui/react-button';
/**
 * Render the final JSX of MessageBarActions
 */ export const renderMessageBarActions_unstable = (state, contexts)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(ButtonContextProvider, {
        value: contexts.button,
        children: [
            state.layout === 'multiline' && state.containerAction && /*#__PURE__*/ _jsx(state.containerAction, {}, "containerAction"),
            /*#__PURE__*/ _jsx(state.root, {}),
            state.layout !== 'multiline' && state.containerAction && /*#__PURE__*/ _jsx(state.containerAction, {}, "containerAction")
        ]
    });
};
