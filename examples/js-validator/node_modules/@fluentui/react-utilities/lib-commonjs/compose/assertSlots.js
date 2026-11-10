"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "assertSlots", {
    enumerable: true,
    get: function() {
        return assertSlots;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _constants = require("./constants");
const _isSlot = require("./isSlot");
const _slot = /*#__PURE__*/ _interop_require_wildcard._(require("./slot"));
function assertSlots(state) {
    /**
   * This verification is not necessary in production
   * as we're verifying static properties that will not change between environments
   */ if (process.env.NODE_ENV !== 'production') {
        const typedState = state;
        // eslint-disable-next-line @typescript-eslint/no-deprecated
        for (const slotName of Object.keys(typedState.components)){
            const slotElement = typedState[slotName];
            if (slotElement === undefined) {
                continue;
            }
            // this means a slot is being declared without using, slot.always or slot.optional or even resolveShorthand on the state hook,
            // but the render method is using the new `assertSlots` method. That scenario can be solved by simply updating the slot element with the proper element type
            // FIXME: this slot will still fail to support child render function scenario
            if (!(0, _isSlot.isSlot)(slotElement)) {
                typedState[slotName] = _slot.always(slotElement, {
                    // eslint-disable-next-line @typescript-eslint/no-deprecated
                    elementType: typedState.components[slotName]
                });
                // eslint-disable-next-line no-console
                console.warn(`@fluentui/react-utilities [${assertSlots.name}]:
"state.${slotName}" is not a slot!
Be sure to create slots properly by using "slot.always" or "slot.optional".`);
            } else {
                // This means a slot is being declared by using resolveShorthand on the state hook,
                // but the render method is using the new `assertSlots` method. That scenario can be solved by simply updating the slot element with the proper element type
                const { [_constants.SLOT_ELEMENT_TYPE_SYMBOL]: elementType } = slotElement;
                // eslint-disable-next-line @typescript-eslint/no-deprecated
                if (elementType !== typedState.components[slotName]) {
                    // eslint-disable-next-line @typescript-eslint/no-deprecated
                    slotElement[_constants.SLOT_ELEMENT_TYPE_SYMBOL] = typedState.components[slotName];
                    // eslint-disable-next-line no-console
                    console.warn(`@fluentui/react-utilities [${assertSlots.name}]:
"state.${slotName}" element type differs from "state.components.${slotName}",
${elementType} !== ${typedState.components[slotName]}.
Be sure to create slots properly by using "slot.always" or "slot.optional" with the correct elementType.`);
                }
            }
        }
    }
}
