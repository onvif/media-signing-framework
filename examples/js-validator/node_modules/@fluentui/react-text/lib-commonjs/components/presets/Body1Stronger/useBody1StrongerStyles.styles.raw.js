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
    body1StrongerClassNames: function() {
        return body1StrongerClassNames;
    },
    useBody1StrongerStyles: function() {
        return useBody1StrongerStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const body1StrongerClassNames = {
    root: 'fui-Body1Stronger'
};
const useBody1StrongerStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.body1Stronger
});
