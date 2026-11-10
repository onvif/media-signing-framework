"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useStyles", {
    enumerable: true,
    get: function() {
        return useStyles;
    }
});
const _react = require("@griffel/react");
const _reacttheme = require("@fluentui/react-theme");
const useStyles = (0, _react.makeStyles)({
    wrapper: {
        display: 'none',
        height: 0,
        width: 0,
        pointerEvents: 'none'
    },
    wrapperActive: {
        display: 'block'
    },
    svg: {
        fill: 'transparent',
        pointerEvents: 'none',
        position: 'fixed',
        top: 0,
        left: 0
    },
    triangle: {
        pointerEvents: 'auto'
    },
    triangleDebug: {
        cursor: 'crosshair',
        fill: `color-mix(in srgb, ${_reacttheme.tokens.colorPaletteGreenBackground3} 20%, transparent)`
    },
    rectDebug: {
        fill: `color-mix(in srgb, ${_reacttheme.tokens.colorPaletteRedBackground3} 20%, transparent)`
    }
});
