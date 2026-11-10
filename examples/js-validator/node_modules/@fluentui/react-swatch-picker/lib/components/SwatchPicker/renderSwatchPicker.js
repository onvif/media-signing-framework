  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { SwatchPickerProvider } from '../../contexts/swatchPicker';
/**
 * Render the final JSX of SwatchPicker
 */ export const renderSwatchPicker_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(SwatchPickerProvider, {
        value: contextValues.swatchPicker,
        children: /*#__PURE__*/ _jsx(state.root, {
            children: state.root.children
        })
    });
};
