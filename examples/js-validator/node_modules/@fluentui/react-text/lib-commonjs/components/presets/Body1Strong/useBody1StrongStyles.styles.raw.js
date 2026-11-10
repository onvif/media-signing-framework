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
    body1StrongClassNames: function() {
        return body1StrongClassNames;
    },
    useBody1StrongStyles: function() {
        return useBody1StrongStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const body1StrongClassNames = {
    root: 'fui-Body1Strong'
};
const useBody1StrongStyles = (0, _react.makeStyles)({
    root: _reacttheme.typographyStyles.body1Strong
});
