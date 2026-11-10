  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
/**
 * Render the final JSX of ColorArea
 */ export const renderColorArea_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(state.root, {
        children: /*#__PURE__*/ _jsxs(state.thumb, {
            children: [
                /*#__PURE__*/ _jsx(state.inputX, {}),
                /*#__PURE__*/ _jsx(state.inputY, {})
            ]
        })
    });
};
