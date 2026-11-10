"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getSlotClassNameProp", {
    enumerable: true,
    get: function() {
        return getSlotClassNameProp;
    }
});
const _constants = require("../compose/constants");
const getSlotClassNameProp = (slot)=>{
    if (_constants.SLOT_CLASS_NAME_PROP_SYMBOL in slot && typeof slot[_constants.SLOT_CLASS_NAME_PROP_SYMBOL] === 'string') {
        return slot[_constants.SLOT_CLASS_NAME_PROP_SYMBOL];
    }
    return undefined;
};
