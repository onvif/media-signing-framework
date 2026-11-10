  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { ActiveDescendantContextProvider } from '@fluentui/react-aria';
import { ListboxContext } from '../../contexts/ListboxContext';
/**
 * Render the final JSX of Listbox
 */ export const renderListbox_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(ActiveDescendantContextProvider, {
        value: contextValues.activeDescendant,
        children: /*#__PURE__*/ _jsx(ListboxContext.Provider, {
            value: contextValues.listbox,
            children: /*#__PURE__*/ _jsx(state.root, {})
        })
    });
};
