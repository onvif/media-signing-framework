"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "drawerSeparatorStyles", {
    enumerable: true,
    get: function() {
        return drawerSeparatorStyles;
    }
});
const _reacttheme = require("@fluentui/react-theme");
const drawerSeparatorStyles = {
    height: '1px',
    position: 'absolute',
    right: 0,
    left: 0,
    opacity: 0,
    backgroundColor: _reacttheme.tokens.colorNeutralStroke1,
    transitionDuration: _reacttheme.tokens.durationNormal,
    transitionProperty: 'opacity',
    transitionTimingFunction: _reacttheme.tokens.curveEasyEase,
    content: '""'
};
