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
    applyTriggerPropsToChildren: function() {
        return _applyTriggerPropsToChildren.applyTriggerPropsToChildren;
    },
    getTriggerChild: function() {
        return _getTriggerChild.getTriggerChild;
    },
    isFluentTrigger: function() {
        return _isFluentTrigger.isFluentTrigger;
    }
});
const _applyTriggerPropsToChildren = require("./applyTriggerPropsToChildren");
const _getTriggerChild = require("./getTriggerChild");
const _isFluentTrigger = require("./isFluentTrigger");
