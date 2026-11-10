/**
 * Calculates the corners of a rectangle based on its DOMRect and an offset.
 *
 * @internal
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "pointsToSvgPath", {
    enumerable: true,
    get: function() {
        return pointsToSvgPath;
    }
});
function pointsToSvgPath(points) {
    return `M ${points} z`;
}
