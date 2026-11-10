  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { Portal } from '@fluentui/react-portal';
import { ActiveDescendantContextProvider } from '@fluentui/react-aria';
import { assertSlots } from '@fluentui/react-utilities';
import { ComboboxContext } from '../../contexts/ComboboxContext';
import { ListboxProvider } from '../../contexts/ListboxContext';
/**
 * Render the final JSX of Combobox
 */ export const renderCombobox_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(state.root, {
        children: /*#__PURE__*/ _jsx(ActiveDescendantContextProvider, {
            value: contextValues.activeDescendant,
            children: /*#__PURE__*/ _jsx(ListboxProvider, {
                value: contextValues.listbox,
                children: /*#__PURE__*/ _jsxs(ComboboxContext.Provider, {
                    value: contextValues.combobox,
                    children: [
                        /*#__PURE__*/ _jsx(state.input, {}),
                        state.clearIcon && /*#__PURE__*/ _jsx(state.clearIcon, {}),
                        state.expandIcon && /*#__PURE__*/ _jsx(state.expandIcon, {}),
                        state.listbox && (state.inlinePopup ? /*#__PURE__*/ _jsx(state.listbox, {}) : /*#__PURE__*/ _jsx(Portal, {
                            mountNode: state.mountNode,
                            children: /*#__PURE__*/ _jsx(state.listbox, {})
                        }))
                    ]
                })
            })
        })
    });
};
