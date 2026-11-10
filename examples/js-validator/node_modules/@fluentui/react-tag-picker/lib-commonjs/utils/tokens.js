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
    tagPickerInputCSSRules: function() {
        return tagPickerInputCSSRules;
    },
    tagPickerInputTokens: function() {
        return tagPickerInputTokens;
    }
});
const tagPickerInputCSSRules = {
    width: '--fluent-TagPickerInput__width'
};
const tagPickerInputTokens = {
    width: `var(${tagPickerInputCSSRules.width}, 0)`
};
