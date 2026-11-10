  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { menuSplitGroupContextDefaultValue, MenuSplitGroupContextProvider } from '../../contexts/menuSplitGroupContext';
/**
 * Render the final JSX of MenuSplitGroup
 */ export const renderMenuSplitGroup_unstable = (state, contexts)=>{
    assertSlots(state);
    var _contexts_menuSplitGroup;
    return /*#__PURE__*/ _jsx(MenuSplitGroupContextProvider, {
        value: (_contexts_menuSplitGroup = contexts === null || contexts === void 0 ? void 0 : contexts.menuSplitGroup) !== null && _contexts_menuSplitGroup !== void 0 ? _contexts_menuSplitGroup : menuSplitGroupContextDefaultValue,
        children: /*#__PURE__*/ _jsx(state.root, {})
    });
};
