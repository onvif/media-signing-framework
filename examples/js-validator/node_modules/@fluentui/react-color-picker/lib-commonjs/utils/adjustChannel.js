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
    adjustChannel: function() {
        return adjustChannel;
    },
    clampValue: function() {
        return clampValue;
    }
});
const _constants = require("./constants");
const _reactutilities = require("@fluentui/react-utilities");
function clampValue(value, channel = 'hue') {
    const MAX = channel === 'hue' ? _constants.HUE_MAX : _constants.MAX;
    return (0, _reactutilities.clamp)(value, _constants.MIN, MAX);
}
function adjustChannel(channel, actions) {
    return actions[channel] || actions.hue;
}
