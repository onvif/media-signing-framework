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
    caption2ClassNames: function() {
        return caption2ClassNames;
    },
    useCaption2Styles: function() {
        return useCaption2Styles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const caption2ClassNames = {
    root: 'fui-Caption2'
};
const useCaption2Styles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.caption2
});
