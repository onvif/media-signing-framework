"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useTeachingPopoverCarouselContextValues_unstable", {
    enumerable: true,
    get: function() {
        return useTeachingPopoverCarouselContextValues_unstable;
    }
});
function useTeachingPopoverCarouselContextValues_unstable(state) {
    const { store, value, selectPageByValue, selectPageByDirection } = state;
    const carousel = {
        store,
        value,
        selectPageByDirection,
        selectPageByValue
    };
    return {
        carousel
    };
}
