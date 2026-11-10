/**
 * Calculates the percentage of a value within a given range.
 *
 * @param value - The value to be converted to a percentage.
 * @param min - The minimum value of the range.
 * @param max - The maximum value of the range.
 * @returns The percentage representation of the value within the range [min, max].
 *          Returns 0 if `min` is equal to `max`.
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getPercent", {
    enumerable: true,
    get: function() {
        return getPercent;
    }
});
const getPercent = (value, min, max)=>{
    return max === min ? 0 : (value - min) / (max - min) * 100;
};
