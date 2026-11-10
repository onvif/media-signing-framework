/**
 * Creates an HSV color object with optional hue, saturation, value, and alpha components.
 *
 * @param {Partial<HsvColor>} param0 - An object containing optional HSV color components:
 *  - `h` (number): The hue component, default is 0.
 *  - `s` (number): The saturation component, default is 0.
 *  - `v` (number): The value component, default is 0.
 *  - `a` (number): The alpha component, default is 1.
 * @returns {HsvColor} The resulting HSV color object.
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "createHsvColor", {
    enumerable: true,
    get: function() {
        return createHsvColor;
    }
});
function createHsvColor({ h = 0, s = 0, v = 0, a = 1 }) {
    return {
        h,
        s,
        v,
        a
    };
}
