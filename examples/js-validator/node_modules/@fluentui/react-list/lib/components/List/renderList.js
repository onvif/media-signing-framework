  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { ListContextProvider, ListSynchronousContextProvider } from './listContext';
/**
 * Render the final JSX of List
 */ export const renderList_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(ListContextProvider, {
        value: contextValues.listContext,
        children: /*#__PURE__*/ _jsx(ListSynchronousContextProvider, {
            value: contextValues.synchronousContext,
            children: /*#__PURE__*/ _jsx(state.root, {})
        })
    });
};
