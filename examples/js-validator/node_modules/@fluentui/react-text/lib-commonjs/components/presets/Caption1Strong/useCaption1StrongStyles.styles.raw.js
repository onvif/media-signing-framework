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
    caption1StrongClassNames: function() {
        return caption1StrongClassNames;
    },
    useCaption1StrongStyles: function() {
        return useCaption1StrongStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const caption1StrongClassNames = {
    root: 'fui-Caption1Strong'
};
const useCaption1StrongStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.caption1Strong
});
