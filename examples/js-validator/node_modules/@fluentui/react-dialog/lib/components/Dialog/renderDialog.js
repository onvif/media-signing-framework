  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import * as React from 'react';
import { MotionRefForwarder } from '../MotionRefForwarder';
import { DialogProvider, DialogSurfaceProvider } from '../../contexts';
/**
 * Render the final JSX of Dialog
 */ export const renderDialog_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(DialogProvider, {
        value: contextValues.dialog,
        children: /*#__PURE__*/ _jsxs(DialogSurfaceProvider, {
            value: contextValues.dialogSurface,
            children: [
                state.trigger,
                state.content && /*#__PURE__*/ _jsx(state.surfaceMotion, {
                    children: /*#__PURE__*/ _jsx(MotionRefForwarder, {
                        children: state.content
                    })
                })
            ]
        })
    });
};
