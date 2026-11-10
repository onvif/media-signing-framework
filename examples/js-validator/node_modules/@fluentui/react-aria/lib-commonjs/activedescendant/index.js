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
    ACTIVEDESCENDANT_ATTRIBUTE: function() {
        return _constants.ACTIVEDESCENDANT_ATTRIBUTE;
    },
    ACTIVEDESCENDANT_FOCUSVISIBLE_ATTRIBUTE: function() {
        return _constants.ACTIVEDESCENDANT_FOCUSVISIBLE_ATTRIBUTE;
    },
    ActiveDescendantContextProvider: function() {
        return _ActiveDescendantContext.ActiveDescendantContextProvider;
    },
    createActiveDescendantChangeEvent: function() {
        return _useActiveDescendant.createActiveDescendantChangeEvent;
    },
    useActiveDescendant: function() {
        return _useActiveDescendant.useActiveDescendant;
    },
    useActiveDescendantContext: function() {
        return _ActiveDescendantContext.useActiveDescendantContext;
    },
    useHasParentActiveDescendantContext: function() {
        return _ActiveDescendantContext.useHasParentActiveDescendantContext;
    }
});
const _ActiveDescendantContext = require("./ActiveDescendantContext");
const _useActiveDescendant = require("./useActiveDescendant");
const _constants = require("./constants");
