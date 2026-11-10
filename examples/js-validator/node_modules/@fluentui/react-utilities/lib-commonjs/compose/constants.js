/**
 * @internal
 * Internal reference for the render function
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
    SLOT_CLASS_NAME_PROP_SYMBOL: function() {
        return SLOT_CLASS_NAME_PROP_SYMBOL;
    },
    SLOT_ELEMENT_TYPE_SYMBOL: function() {
        return SLOT_ELEMENT_TYPE_SYMBOL;
    },
    SLOT_RENDER_FUNCTION_SYMBOL: function() {
        return SLOT_RENDER_FUNCTION_SYMBOL;
    }
});
const SLOT_RENDER_FUNCTION_SYMBOL = Symbol.for('fui.slotRenderFunction');
const SLOT_ELEMENT_TYPE_SYMBOL = Symbol.for('fui.slotElementType');
const SLOT_CLASS_NAME_PROP_SYMBOL = Symbol.for('fui.slotClassNameProp');
