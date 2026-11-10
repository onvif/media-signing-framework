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
    displayClassNames: function() {
        return displayClassNames;
    },
    useDisplayStyles: function() {
        return useDisplayStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const displayClassNames = {
    root: 'fui-Display'
};
const useDisplayStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.display
});
