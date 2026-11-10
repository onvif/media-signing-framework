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
    getCoordinates: function() {
        return getCoordinates;
    },
    roundTwoDecimal: function() {
        return roundTwoDecimal;
    }
});
const _reactutilities = require("@fluentui/react-utilities");
function getCoordinates(element, event) {
    const rect = element.getBoundingClientRect();
    const newX = roundTwoDecimal((event.clientX - rect.left) / rect.width);
    const newY = roundTwoDecimal(1 - (event.clientY - rect.top) / rect.height);
    return {
        x: (0, _reactutilities.clamp)(newX, 0, 1),
        y: (0, _reactutilities.clamp)(newY, 0, 1)
    };
}
function roundTwoDecimal(num) {
    return Math.round(num * 100) / 100;
}
