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
    CarouselProvider: function() {
        return _CarouselContext.CarouselProvider;
    },
    carouselContextDefaultValue: function() {
        return _CarouselContext.carouselContextDefaultValue;
    },
    useCarouselContext_unstable: function() {
        return _CarouselContext.useCarouselContext_unstable;
    }
});
const _CarouselContext = require("./components/CarouselContext");
