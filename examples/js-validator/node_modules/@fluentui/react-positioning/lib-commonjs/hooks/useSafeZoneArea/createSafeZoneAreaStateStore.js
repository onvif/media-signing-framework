"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "createSafeZoneAreaStateStore", {
    enumerable: true,
    get: function() {
        return createSafeZoneAreaStateStore;
    }
});
function createSafeZoneAreaStateStore() {
    let isActive = false;
    const listeners = [];
    return {
        isActive () {
            return isActive;
        },
        toggleActive (newIsActive) {
            if (isActive === newIsActive) {
                return;
            }
            isActive = newIsActive;
            listeners.forEach((listener)=>listener(isActive));
        },
        subscribe (listener) {
            listeners.push(listener);
            return ()=>{
                const index = listeners.indexOf(listener);
                if (index > -1) {
                    listeners.splice(index, 1);
                }
            };
        }
    };
}
