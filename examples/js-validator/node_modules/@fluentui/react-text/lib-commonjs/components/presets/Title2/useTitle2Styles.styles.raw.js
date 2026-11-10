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
    title2ClassNames: function() {
        return title2ClassNames;
    },
    useTitle2Styles: function() {
        return useTitle2Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const title2ClassNames = {
    root: 'fui-Title2'
};
const useTitle2Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.title2
});
