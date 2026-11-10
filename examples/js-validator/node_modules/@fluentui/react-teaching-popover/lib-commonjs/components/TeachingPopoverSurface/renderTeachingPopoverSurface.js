"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverSurface_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverSurface_unstable;
    }
});
const _reactutilities = require("@fluentui/react-utilities");
const _reactpopover = require("@fluentui/react-popover");
const renderTeachingPopoverSurface_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    // For now we are just extending the base surface
    return (0, _reactpopover.renderPopoverSurface_unstable)(state);
};
