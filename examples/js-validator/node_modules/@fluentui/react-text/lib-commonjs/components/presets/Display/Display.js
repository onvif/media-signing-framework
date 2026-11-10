"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "Display", {
    enumerable: true,
    get: function() {
        return Display;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _createPreset = require("../createPreset");
const _useDisplayStylesstyles = require("./useDisplayStyles.styles");
const Display = (0, _createPreset.createPreset)({
    useStyles: _useDisplayStylesstyles.useDisplayStyles,
    className: _useDisplayStylesstyles.displayClassNames.root,
    displayName: 'Display'
});
