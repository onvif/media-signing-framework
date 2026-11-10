  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { ColorPickerProvider } from '../../contexts/colorPicker';
/**
 * Render the final JSX of ColorPicker
 */ export const renderColorPicker_unstable = (state, contextValues)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(ColorPickerProvider, {
        value: contextValues.colorPicker,
        children: /*#__PURE__*/ _jsx(state.root, {
            children: state.root.children
        })
    });
};
