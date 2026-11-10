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
    subtitle2StrongerClassNames: function() {
        return subtitle2StrongerClassNames;
    },
    useSubtitle2StrongerStyles: function() {
        return useSubtitle2StrongerStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const subtitle2StrongerClassNames = {
    root: 'fui-Subtitle2Stronger'
};
const useSubtitle2StrongerStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.subtitle2Stronger
});
