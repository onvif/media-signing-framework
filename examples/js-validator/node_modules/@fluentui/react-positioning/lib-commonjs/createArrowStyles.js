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
    createArrowHeightStyles: function() {
        return createArrowHeightStyles;
    },
    createArrowStyles: function() {
        return createArrowStyles;
    }
});
const _reacttheme = require("@fluentui/react-theme");
function createArrowStyles(options) {
    const { arrowHeight, borderWidth = '1px', borderStyle = 'solid', borderColor = _reacttheme.tokens.colorTransparentStroke } = options;
    return {
        boxSizing: 'border-box',
        position: 'absolute',
        zIndex: -1,
        ...arrowHeight && createArrowHeightStyles(arrowHeight),
        backgroundColor: 'inherit',
        backgroundClip: 'content-box',
        borderBottomLeftRadius: `${_reacttheme.tokens.borderRadiusSmall} /* @noflip */`,
        transform: 'rotate(var(--fui-positioning-arrow-angle)) /* @noflip */',
        height: 'var(--fui-positioning-arrow-height)',
        width: 'var(--fui-positioning-arrow-height)',
        '::before': {
            content: '""',
            display: 'block',
            backgroundColor: 'inherit',
            margin: `-${borderWidth}`,
            width: '100%',
            height: '100%',
            border: `${borderWidth} ${borderStyle} ${borderColor}`,
            borderBottomLeftRadius: `${_reacttheme.tokens.borderRadiusSmall} /* @noflip */`,
            clipPath: 'polygon(0% 0%, 100% 100%, 0% 100%)'
        },
        // Popper sets data-popper-placement on the root element, which is used to align the arrow
        ':global([data-popper-placement^="top"])': {
            bottom: 'var(--fui-positioning-arrow-offset)',
            '--fui-positioning-arrow-angle': '-45deg'
        },
        ':global([data-popper-placement^="right"])': {
            left: `var(--fui-positioning-arrow-offset) /* @noflip */`,
            '--fui-positioning-arrow-angle': '45deg'
        },
        ':global([data-popper-placement^="bottom"])': {
            top: 'var(--fui-positioning-arrow-offset)',
            '--fui-positioning-arrow-angle': '135deg'
        },
        ':global([data-popper-placement^="left"])': {
            right: `var(--fui-positioning-arrow-offset) /* @noflip */`,
            '--fui-positioning-arrow-angle': '225deg'
        }
    };
}
function createArrowHeightStyles(arrowHeight) {
    // The arrow is a square rotated 45 degrees to have its bottom and right edges form a right triangle.
    // Multiply the triangle's height by sqrt(2) to get length of its edges.
    const edgeLength = 1.414 * arrowHeight;
    return {
        '--fui-positioning-arrow-height': `${edgeLength}px`,
        '--fui-positioning-arrow-offset': `${edgeLength / 2 * -1}px`
    };
}
