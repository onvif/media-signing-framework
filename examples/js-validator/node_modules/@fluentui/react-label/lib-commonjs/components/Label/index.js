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
    Label: function() {
        return _Label.Label;
    },
    labelClassNames: function() {
        return _useLabelStylesstyles.labelClassNames;
    },
    renderLabel_unstable: function() {
        return _renderLabel.renderLabel_unstable;
    },
    useLabelStyles_unstable: function() {
        return _useLabelStylesstyles.useLabelStyles_unstable;
    },
    useLabel_unstable: function() {
        return _useLabel.useLabel_unstable;
    }
});
const _Label = require("./Label");
const _renderLabel = require("./renderLabel");
const _useLabel = require("./useLabel");
const _useLabelStylesstyles = require("./useLabelStyles.styles");
