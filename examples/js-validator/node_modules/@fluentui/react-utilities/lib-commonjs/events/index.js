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
    getEventClientCoords: function() {
        return _mouseTouchHelpers.getEventClientCoords;
    },
    isMouseEvent: function() {
        return _mouseTouchHelpers.isMouseEvent;
    },
    isTouchEvent: function() {
        return _mouseTouchHelpers.isTouchEvent;
    }
});
const _mouseTouchHelpers = require("./mouseTouchHelpers");
