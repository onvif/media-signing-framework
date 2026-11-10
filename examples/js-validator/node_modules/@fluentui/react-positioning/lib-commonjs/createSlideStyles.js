"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "createSlideStyles", {
    enumerable: true,
    get: function() {
        return createSlideStyles;
    }
});
const _reacttheme = require("@fluentui/react-theme");
const _constants = require("./constants");
function createSlideStyles(mainAxis) {
    // With 'accumulate' animation composition, these opacity keyframes are added onto the default opacity of 1.
    const fadeIn = {
        from: {
            opacity: -1
        },
        to: {
            opacity: 0
        }
    };
    const slideDistanceVarX = '--fui-positioning-slide-distance-x';
    const slideDistanceVarY = '--fui-positioning-slide-distance-y';
    return {
        // NOTE: there was a previous attempt to give fadeIn a separate composition mode:
        //   animationComposition: 'replace, accumulate',
        // but somehow this was linked to a performance regression observed in Teams (bug #4255933)
        animationComposition: 'accumulate',
        animationDuration: _reacttheme.tokens.durationSlower,
        animationTimingFunction: _reacttheme.tokens.curveDecelerateMid,
        [slideDistanceVarX]: `0px`,
        [slideDistanceVarY]: `${mainAxis}px`,
        [`&[${_constants.DATA_POSITIONING_PLACEMENT}^=right]`]: {
            [slideDistanceVarX]: `-${mainAxis}px`,
            [slideDistanceVarY]: '0px'
        },
        [`&[${_constants.DATA_POSITIONING_PLACEMENT}^=bottom]`]: {
            [slideDistanceVarX]: '0px',
            [slideDistanceVarY]: `-${mainAxis}px`
        },
        [`&[${_constants.DATA_POSITIONING_PLACEMENT}^=left]`]: {
            [slideDistanceVarX]: `${mainAxis}px`,
            [slideDistanceVarY]: '0px'
        },
        animationName: [
            fadeIn,
            {
                from: {
                    transform: `translate(var(${slideDistanceVarX}), var(${slideDistanceVarY}))`
                },
                to: {}
            }
        ],
        // Note: at-rules have more specificity in Griffel
        '@media(prefers-reduced-motion)': {
            [`&[${_constants.DATA_POSITIONING_PLACEMENT}]`]: {
                animationDuration: '1ms',
                animationName: fadeIn
            }
        },
        // Tested in Firefox 79
        '@supports not (animation-composition: accumulate)': {
            [`&[${_constants.DATA_POSITIONING_PLACEMENT}]`]: {
                animationName: fadeIn
            }
        }
    };
}
