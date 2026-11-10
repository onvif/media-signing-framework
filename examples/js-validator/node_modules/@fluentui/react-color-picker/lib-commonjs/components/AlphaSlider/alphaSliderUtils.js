/**
 * Adjusts the given value based on the transparency flag.
 *
 * @param value - The numeric value to adjust.
 * @param transparency - A boolean flag indicating whether to adjust for transparency.
 * @returns The adjusted value.
 */ "use strict";
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
    adjustToTransparency: function() {
        return adjustToTransparency;
    },
    calculateTransparencyValue: function() {
        return calculateTransparencyValue;
    },
    getSliderDirection: function() {
        return getSliderDirection;
    }
});
function adjustToTransparency(value, transparency) {
    return transparency ? 100 - value : value;
}
function calculateTransparencyValue(transparency, value) {
    return value !== undefined ? adjustToTransparency(value * 100, transparency) : undefined;
}
function getSliderDirection(dir, vertical, transparency) {
    if (vertical) {
        return transparency ? '180deg' : '0deg';
    }
    return dir === 'ltr' && !transparency ? '90deg' : '-90deg';
}
