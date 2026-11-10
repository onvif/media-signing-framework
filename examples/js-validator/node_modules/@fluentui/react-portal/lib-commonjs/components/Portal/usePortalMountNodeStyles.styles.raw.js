"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "usePortalMountNodeStylesStyles", {
    enumerable: true,
    get: function() {
        return usePortalMountNodeStylesStyles;
    }
});
const _react = require("@griffel/react");
const usePortalMountNodeStylesStyles = (0, _react.makeStyles)({
    root: {
        // Creates new stacking context to prevent z-index issues
        // https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_positioned_layout/Understanding_z-index/Stacking_context
        //
        // Also keeps a portal on top of a page to prevent scrollbars from appearing
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 1000000
    }
});
