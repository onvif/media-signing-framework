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
    caption2StrongClassNames: function() {
        return caption2StrongClassNames;
    },
    useCaption2StrongStyles: function() {
        return useCaption2StrongStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const caption2StrongClassNames = {
    root: 'fui-Caption2Strong'
};
const useCaption2StrongStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.caption2Strong
});
