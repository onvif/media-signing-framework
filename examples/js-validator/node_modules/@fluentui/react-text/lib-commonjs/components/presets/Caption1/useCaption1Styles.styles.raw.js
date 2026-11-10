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
    caption1ClassNames: function() {
        return caption1ClassNames;
    },
    useCaption1Styles: function() {
        return useCaption1Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const caption1ClassNames = {
    root: 'fui-Caption1'
};
const useCaption1Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.caption1
});
