"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderSwatchPicker_unstable", {
    enumerable: true,
    get: function() {
        return renderSwatchPicker_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _swatchPicker = require("../../contexts/swatchPicker");
const renderSwatchPicker_unstable = (state, contextValues)=>{
    (0, _reactutilities.assertSlots)(state);
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(_swatchPicker.SwatchPickerProvider, {
        value: contextValues.swatchPicker,
        children: /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {
            children: state.root.children
        })
    });
};
