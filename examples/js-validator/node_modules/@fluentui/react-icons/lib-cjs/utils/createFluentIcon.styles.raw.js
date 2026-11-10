"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useRootStyles = void 0;
const react_1 = require("@griffel/react");
exports.useRootStyles = react_1.makeStyles({
    root: {
        // This style is required because browsers automatically have SVGs set to
        // forced-color-adjust: preserve-parent-color, which will not override
        // internally-defined colors in our SVG icons in high contrast mode.
        "@media (forced-colors: active)": {
            forcedColorAdjust: "auto",
        },
    },
});
