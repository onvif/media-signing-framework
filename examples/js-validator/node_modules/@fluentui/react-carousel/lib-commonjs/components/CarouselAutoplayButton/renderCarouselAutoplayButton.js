"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderCarouselAutoplayButton_unstable", {
    enumerable: true,
    get: function() {
        return renderCarouselAutoplayButton_unstable;
    }
});
const _reactutilities = require("@fluentui/react-utilities");
const _reactbutton = require("@fluentui/react-button");
const renderCarouselAutoplayButton_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    // We render the underlying react-button with injected carousel functionality
    return (0, _reactbutton.renderToggleButton_unstable)(state);
};
