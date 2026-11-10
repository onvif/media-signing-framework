  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { Portal } from '@fluentui/react-portal';
import { assertSlots } from '@fluentui/react-utilities';
import { ActiveDescendantContextProvider } from '@fluentui/react-aria';
import { ComboboxContext } from '../../contexts/ComboboxContext';
import { ListboxContext } from '../../contexts/ListboxContext';
/**
 * Render the final JSX of Dropdown
 */ export const renderDropdown_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(state.root, {
        children: /*#__PURE__*/ _jsx(ActiveDescendantContextProvider, {
            value: contextValues.activeDescendant,
            children: /*#__PURE__*/ _jsx(ListboxContext.Provider, {
                value: contextValues.listbox,
                children: /*#__PURE__*/ _jsxs(ComboboxContext.Provider, {
                    value: contextValues.combobox,
                    children: [
                        /*#__PURE__*/ _jsxs(state.button, {
                            children: [
                                state.button.children,
                                state.expandIcon && /*#__PURE__*/ _jsx(state.expandIcon, {})
                            ]
                        }),
                        state.clearButton && /*#__PURE__*/ _jsx(state.clearButton, {}),
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
