  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { TreeProvider } from '../TreeProvider';
export const renderTree_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(TreeProvider, {
        value: contextValues.tree,
        children: state.collapseMotion ? /*#__PURE__*/ _jsx(state.collapseMotion, {
            children: /*#__PURE__*/ _jsx(state.root, {})
        }) : /*#__PURE__*/ _jsx(state.root, {})
    });
};
