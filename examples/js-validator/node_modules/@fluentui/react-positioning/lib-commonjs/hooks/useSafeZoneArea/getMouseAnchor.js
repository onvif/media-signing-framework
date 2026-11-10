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
    getMouseAnchor: function() {
        return getMouseAnchor;
    },
    getUnitVector: function() {
        return getUnitVector;
    },
    measureDistance: function() {
        return measureDistance;
    }
});
const OFFSET_DISTANCE = 20;
function measureDistance(a, b) {
    return Math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2);
}
function getUnitVector(a, b) {
    const distance = measureDistance(a, b);
    if (distance === 0) {
        return [
            0,
            0
        ];
    }
    return [
        (a[0] - b[0]) / distance,
        (a[1] - b[1]) / distance
    ];
}
function getMouseAnchor(topLeftCorner, bottomRightCorner, mouseCoordinates) {
    const containerCenter = [
        (topLeftCorner[0] + bottomRightCorner[0]) / 2,
        (topLeftCorner[1] + bottomRightCorner[1]) / 2
    ];
    const unitVector = getUnitVector([
        mouseCoordinates[0],
        mouseCoordinates[1]
    ], [
        containerCenter[0],
        containerCenter[1]
    ]);
    const distance = measureDistance([
        containerCenter[0],
        containerCenter[1]
    ], [
        mouseCoordinates[0],
        mouseCoordinates[1]
    ]);
    return [
        containerCenter[0] + unitVector[0] * (distance + OFFSET_DISTANCE),
        containerCenter[1] + unitVector[1] * (distance + OFFSET_DISTANCE)
    ];
}
