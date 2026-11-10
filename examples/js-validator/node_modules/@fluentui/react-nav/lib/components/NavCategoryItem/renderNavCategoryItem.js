  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { NavCategoryItemProvider } from '../NavCategoryItemContext';
const getExpandIcon = (state)=>{
    assertSlots(state);
    if (!state.expandIcon) {
        return null;
    }
    if (!state.expandIconMotion) {
        return /*#__PURE__*/ _jsx(state.expandIcon, {});
    }
    return /*#__PURE__*/ _jsx(state.expandIconMotion, {
        children: /*#__PURE__*/ _jsx(state.expandIcon, {})
    });
};
/**
 * Render the final JSX of NavCategoryItem
 */ export const renderNavCategoryItem_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(NavCategoryItemProvider, {
        value: contextValues.navCategoryItem,
        children: /*#__PURE__*/ _jsxs(state.root, {
            children: [
                state.icon && /*#__PURE__*/ _jsx(state.icon, {}),
                state.root.children,
                getExpandIcon(state)
            ]
        })
    });
};
