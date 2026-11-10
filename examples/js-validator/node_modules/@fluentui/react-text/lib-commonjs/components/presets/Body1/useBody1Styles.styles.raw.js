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
    body1ClassNames: function() {
        return body1ClassNames;
    },
    useBody1Styles: function() {
        return useBody1Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const body1ClassNames = {
    root: 'fui-Body1'
};
const useBody1Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.body1
});
