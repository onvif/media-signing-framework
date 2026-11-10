"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getDropdownActionFromKey", {
    enumerable: true,
    get: function() {
        return getDropdownActionFromKey;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _keyboardkeys = /*#__PURE__*/ _interop_require_wildcard._(require("@fluentui/keyboard-keys"));
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
function getDropdownActionFromKey(e, options = {}) {
    const { open = true, multiselect = false } = options;
    const code = e.key;
    const { altKey, ctrlKey, key, metaKey } = e;
    // typing action occurs whether open or closed
    if (key.length === 1 && code !== _keyboardkeys.Space && !altKey && !ctrlKey && !metaKey) {
        return 'Type';
    }
    // handle opening the dropdown if closed
    if (!open) {
        if (code === _keyboardkeys.ArrowDown || code === _keyboardkeys.ArrowUp || code === _keyboardkeys.Enter || code === _keyboardkeys.Space) {
            return 'Open';
        }
        // if the dropdown is closed and an action did not match the above, do nothing
        return 'None';
    }
    // select or close actions
    if (code === _keyboardkeys.ArrowUp && altKey || code === _keyboardkeys.Enter || !multiselect && code === _keyboardkeys.Space) {
        return 'CloseSelect';
    }
    if (multiselect && code === _keyboardkeys.Space) {
        return 'Select';
    }
    if (code === _keyboardkeys.Escape) {
        return 'Close';
    }
    // navigation interactions
    if (code === _keyboardkeys.ArrowDown) {
        return 'Next';
    }
    if (code === _keyboardkeys.ArrowUp) {
        return 'Previous';
    }
    if (code === _keyboardkeys.Home) {
        return 'First';
    }
    if (code === _keyboardkeys.End) {
        return 'Last';
    }
    if (code === _keyboardkeys.PageUp) {
        return 'PageUp';
    }
    if (code === _keyboardkeys.PageDown) {
        return 'PageDown';
    }
    if (code === _keyboardkeys.Tab) {
        return 'Tab';
    }
    // if nothing matched, return none
    return 'None';
}
