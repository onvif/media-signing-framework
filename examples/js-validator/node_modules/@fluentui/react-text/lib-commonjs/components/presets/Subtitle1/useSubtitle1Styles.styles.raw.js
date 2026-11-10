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
    subtitle1ClassNames: function() {
        return subtitle1ClassNames;
    },
    useSubtitle1Styles: function() {
        return useSubtitle1Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const subtitle1ClassNames = {
    root: 'fui-Subtitle1'
};
const useSubtitle1Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.subtitle1
});
