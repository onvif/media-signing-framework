"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    SwatchPickerProvider: function() {
        return _swatchPicker.SwatchPickerProvider;
    },
    swatchPickerContextDefaultValue: function() {
        return _swatchPicker.swatchPickerContextDefaultValue;
    },
    useSwatchPickerContextValue_unstable: function() {
        return _swatchPicker.useSwatchPickerContextValue_unstable;
    },
    useSwatchPickerContextValues: function() {
        return _swatchPicker.useSwatchPickerContextValues;
    }
});
const _swatchPicker = require("./swatchPicker");
