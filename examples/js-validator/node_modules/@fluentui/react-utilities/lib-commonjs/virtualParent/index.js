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
    elementContains: function() {
        return _elementContains.elementContains;
    },
    getParent: function() {
        return _getParent.getParent;
    },
    setVirtualParent: function() {
        return _setVirtualParent.setVirtualParent;
    }
});
const _elementContains = require("./elementContains");
const _setVirtualParent = require("./setVirtualParent");
const _getParent = require("./getParent");
