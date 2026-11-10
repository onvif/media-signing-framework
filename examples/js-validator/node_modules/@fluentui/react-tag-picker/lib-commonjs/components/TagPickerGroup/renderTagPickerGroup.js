"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTagPickerGroup_unstable", {
    enumerable: true,
    get: function() {
        return renderTagPickerGroup_unstable;
    }
});
const _reacttags = require("@fluentui/react-tags");
function renderTagPickerGroup_unstable(state, contexts) {
    if (!state.hasSelectedOptions) {
        return null;
    }
    return (0, _reacttags.renderTagGroup_unstable)(state, contexts);
}
