"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderColorPicker_unstable", {
    enumerable: true,
    get: function() {
        return renderColorPicker_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _colorPicker = require("../../contexts/colorPicker");
const renderColorPicker_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_colorPicker.ColorPickerProvider, {
        value: contextValues.colorPicker,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {
            children: state.root.children
        })
    });
};
