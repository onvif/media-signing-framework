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
    calculatePrecision: function() {
        return _precision.calculatePrecision;
    },
    clamp: function() {
        return _clamp.clamp;
    },
    getBound: function() {
        return _getBound.getBound;
    },
    precisionRound: function() {
        return _precision.precisionRound;
    }
});
const _clamp = require("./clamp");
const _getBound = require("./getBound");
const _precision = require("./precision");
