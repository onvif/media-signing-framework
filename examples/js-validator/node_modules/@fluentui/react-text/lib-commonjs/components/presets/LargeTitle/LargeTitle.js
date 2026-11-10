"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "LargeTitle", {
    enumerable: true,
    get: function() {
        return LargeTitle;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _createPreset = require("../createPreset");
const _useLargeTitleStylesstyles = require("./useLargeTitleStyles.styles");
const LargeTitle = (0, _createPreset.createPreset)({
    useStyles: _useLargeTitleStylesstyles.useLargeTitleStyles,
    className: _useLargeTitleStylesstyles.largeTitleClassNames.root,
    displayName: 'LargeTitle'
});
