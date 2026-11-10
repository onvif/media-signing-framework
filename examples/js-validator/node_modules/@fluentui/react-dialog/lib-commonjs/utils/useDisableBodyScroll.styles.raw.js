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
    useBodyNoScrollStyles: function() {
        return useBodyNoScrollStyles;
    },
    useHTMLNoScrollStyles: function() {
        return useHTMLNoScrollStyles;
    }
});
const _react = require("@griffel/react");
const useHTMLNoScrollStyles = (0, _react.makeResetStyles)({
    overflowY: [
        'hidden',
        'clip'
    ],
    scrollbarGutter: 'stable'
});
const useBodyNoScrollStyles = (0, _react.makeResetStyles)({
    overflowY: 'hidden'
});
