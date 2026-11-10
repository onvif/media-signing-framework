/**
 * Calculates the corners of a rectangle based on its DOMRect and an offset.
 *
 * @internal
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getRectCorners", {
    enumerable: true,
    get: function() {
        return getRectCorners;
    }
});
function getRectCorners(rect, offset) {
    return {
        topLeft: [
            rect.left - offset[0],
            rect.top - offset[1]
        ],
        topRight: [
            rect.right - offset[0],
            rect.top - offset[1]
        ],
        bottomRight: [
            rect.right - offset[0],
            rect.bottom - offset[1]
        ],
        bottomLeft: [
            rect.left - offset[0],
            rect.bottom - offset[1]
        ]
    };
}
