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
    title3ClassNames: function() {
        return title3ClassNames;
    },
    useTitle3Styles: function() {
        return useTitle3Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const title3ClassNames = {
    root: 'fui-Title3'
};
const useTitle3Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.title3
});
