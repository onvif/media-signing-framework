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
    caption1StrongerClassNames: function() {
        return caption1StrongerClassNames;
    },
    useCaption1StrongerStyles: function() {
        return useCaption1StrongerStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const caption1StrongerClassNames = {
    root: 'fui-Caption1Stronger'
};
const useCaption1StrongerStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.caption1Stronger
});
