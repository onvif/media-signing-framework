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
    Spinner: function() {
        return _Spinner.Spinner;
    },
    SpinnerContextProvider: function() {
        return _index.SpinnerContextProvider;
    },
    renderSpinner_unstable: function() {
        return _Spinner.renderSpinner_unstable;
    },
    spinnerClassNames: function() {
        return _Spinner.spinnerClassNames;
    },
    useSpinnerContext: function() {
        return _index.useSpinnerContext;
    },
    useSpinnerStyles_unstable: function() {
        return _Spinner.useSpinnerStyles_unstable;
    },
    useSpinner_unstable: function() {
        return _Spinner.useSpinner_unstable;
    }
});
const _Spinner = require("./Spinner");
const _index = require("./contexts/index");
