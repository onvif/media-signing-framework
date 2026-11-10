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
    subtitle2ClassNames: function() {
        return subtitle2ClassNames;
    },
    useSubtitle2Styles: function() {
        return useSubtitle2Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const subtitle2ClassNames = {
    root: 'fui-Subtitle2'
};
const useSubtitle2Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.subtitle2
});
