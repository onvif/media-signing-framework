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
    largeTitleClassNames: function() {
        return largeTitleClassNames;
    },
    useLargeTitleStyles: function() {
        return useLargeTitleStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const largeTitleClassNames = {
    root: 'fui-LargeTitle'
};
const useLargeTitleStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.largeTitle
});
