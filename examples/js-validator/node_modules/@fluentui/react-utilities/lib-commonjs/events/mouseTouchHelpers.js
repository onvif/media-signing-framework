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
        return getEventClientCoords;
    },
    isMouseEvent: function() {
        return isMouseEvent;
    },
    isTouchEvent: function() {
        return isTouchEvent;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
function isTouchEvent(event) {
    return event.type.startsWith('touch');
}
function isMouseEvent(event) {
    return event.type.startsWith('mouse') || [
        'click',
        'contextmenu',
        'dblclick'
    ].indexOf(event.type) > -1;
}
function getEventClientCoords(event) {
    if (isMouseEvent(event)) {
        return {
            clientX: event.clientX,
            clientY: event.clientY
        };
    } else if (isTouchEvent(event)) {
        return {
            clientX: event.touches[0].clientX,
            clientY: event.touches[0].clientY
        };
    } else {
        if (process.env.NODE_ENV !== 'production') {
            throw new Error('@fluentui/react-utilities]: Unable to get clientX. Unknown event type.');
        }
        return {
            clientX: 0,
            clientY: 0
        };
    }
}
