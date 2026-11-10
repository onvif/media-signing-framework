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
    HUE_MAX: function() {
        return HUE_MAX;
    },
    INITIAL_COLOR: function() {
        return INITIAL_COLOR;
    },
    INITIAL_COLOR_HSV: function() {
        return INITIAL_COLOR_HSV;
    },
    MAX: function() {
        return MAX;
    },
    MIN: function() {
        return MIN;
    }
});
const _tinycolor = require("@ctrl/tinycolor");
const MIN = 0;
const MAX = 100;
const HUE_MAX = 360;
const INITIAL_COLOR = '#FFF';
const INITIAL_COLOR_HSV = (0, _tinycolor.tinycolor)(INITIAL_COLOR).toHsv();
