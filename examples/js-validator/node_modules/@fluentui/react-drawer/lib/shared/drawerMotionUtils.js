import * as React from 'react';
/**
 * @internal
 * @todo Drawer is a first component to use this pattern, we should move this to a shared package if it will be used in more components
 */ export function mergePresenceSlots(inputSlot, Component, params) {
    if (inputSlot === null) {
        return null;
    }
    return {
        ...inputSlot,
        children: (_, props)=>{
            if (inputSlot === null || inputSlot === void 0 ? void 0 : inputSlot.children) {
                return inputSlot.children(Component, {
                    ...props,
                    ...params
                });
            }
            return /*#__PURE__*/ React.createElement(Component, {
                ...props,
                ...params
            }, props.children);
        }
    };
}
