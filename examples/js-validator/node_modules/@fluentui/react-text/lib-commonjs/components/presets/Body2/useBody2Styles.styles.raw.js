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
    body2ClassNames: function() {
        return body2ClassNames;
    },
    useBody2Styles: function() {
        return useBody2Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const body2ClassNames = {
    root: 'fui-Body2'
};
const useBody2Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.body2
});
