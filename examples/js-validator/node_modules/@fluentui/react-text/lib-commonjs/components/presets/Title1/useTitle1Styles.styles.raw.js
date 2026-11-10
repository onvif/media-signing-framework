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
    title1ClassNames: function() {
        return title1ClassNames;
    },
    useTitle1Styles: function() {
        return useTitle1Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const title1ClassNames = {
    root: 'fui-Title1'
};
const useTitle1Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.title1
});
