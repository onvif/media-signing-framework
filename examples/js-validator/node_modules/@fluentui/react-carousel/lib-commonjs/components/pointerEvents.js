"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "pointerEventPlugin", {
    enumerable: true,
    get: function() {
        return pointerEventPlugin;
    }
});
const _Carousel = require("../Carousel");
function pointerEventPlugin(options) {
    let emblaApi;
    let pointerEvent;
    let carouselListenerTarget;
    /**
   * Heads up!
   *
   * We don't use `emblaApi.on('pointerDown', ...)` as the callback does not provide the event.
   */ function documentDownListener(event) {
        if (event.target) {
            const targetNode = event.target;
            if (targetNode.classList.contains(_Carousel.carouselClassNames.root) || (carouselListenerTarget === null || carouselListenerTarget === void 0 ? void 0 : carouselListenerTarget.contains(targetNode))) {
                pointerEvent = event;
            }
        }
        if (carouselListenerTarget) {
            carouselListenerTarget.removeEventListener('mousedown', documentDownListener);
            carouselListenerTarget.removeEventListener('pointerdown', documentDownListener);
        }
    }
    function pointerUpListener() {
        if (carouselListenerTarget) {
            carouselListenerTarget.addEventListener('mousedown', documentDownListener);
            carouselListenerTarget.addEventListener('pointerdown', documentDownListener);
        }
    }
    function clearPointerEvent() {
        pointerEvent = undefined;
        pointerUpListener();
    }
    function selectListener() {
        if (pointerEvent) {
            var _emblaApi_selectedScrollSnap;
            const newIndex = (_emblaApi_selectedScrollSnap = emblaApi.selectedScrollSnap()) !== null && _emblaApi_selectedScrollSnap !== void 0 ? _emblaApi_selectedScrollSnap : 0;
            options.onSelectViaDrag(pointerEvent, newIndex);
        }
    }
    function init(emblaApiInstance, optionsHandler) {
        emblaApi = emblaApiInstance;
        // Initialize the listener for first mouse/pointerDown event
        carouselListenerTarget = emblaApi.containerNode();
        carouselListenerTarget.addEventListener('mousedown', documentDownListener);
        carouselListenerTarget.addEventListener('pointerdown', documentDownListener);
        emblaApi.on('pointerUp', pointerUpListener);
        emblaApi.on('select', selectListener);
        // Settle is used to clear pointer and conclude drag event
        emblaApi.on('settle', clearPointerEvent);
    }
    function destroy() {
        if (carouselListenerTarget) {
            carouselListenerTarget.removeEventListener('mousedown', documentDownListener);
            carouselListenerTarget.removeEventListener('pointerdown', documentDownListener);
        }
        carouselListenerTarget = undefined;
        emblaApi.off('pointerUp', pointerUpListener);
        emblaApi.off('select', selectListener);
        emblaApi.off('settle', clearPointerEvent);
    }
    return {
        name: 'pointerEvent',
        options,
        init,
        destroy
    };
}
