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
const useHTMLNoScrollStyles = /*#__PURE__*/ (0, _react.__resetStyles)("r6pzz3z", null, [
    ".r6pzz3z{overflow-y:hidden;overflow-y:clip;scrollbar-gutter:stable;}"
]);
const useBodyNoScrollStyles = /*#__PURE__*/ (0, _react.__resetStyles)("r144vlu9", null, [
    ".r144vlu9{overflow-y:hidden;}"
]);
