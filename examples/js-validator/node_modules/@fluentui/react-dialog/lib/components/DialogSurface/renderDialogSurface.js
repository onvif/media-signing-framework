  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { Portal } from '@fluentui/react-portal';
import { assertSlots } from '@fluentui/react-utilities';
import { DialogSurfaceProvider } from '../../contexts';
/**
 * Render the final JSX of DialogSurface
 */ export const renderDialogSurface_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(Portal, {
        mountNode: state.mountNode,
        children: [
            state.backdrop && // TODO: state.backdropMotion is non nullable, but assertSlots asserts it as nullable
            // FIXME: this should be resolved by properly splitting props and state slots declaration
            state.backdropMotion && /*#__PURE__*/ _jsx(state.backdropMotion, {
                children: /*#__PURE__*/ _jsx(state.backdrop, {})
            }),
            /*#__PURE__*/ _jsx(DialogSurfaceProvider, {
                value: contextValues.dialogSurface,
                children: /*#__PURE__*/ _jsx(state.root, {})
            })
        ]
    });
};
