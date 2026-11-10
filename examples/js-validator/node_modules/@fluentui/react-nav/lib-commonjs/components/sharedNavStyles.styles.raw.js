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
    navItemTokens: function() {
        return navItemTokens;
    },
    useContentStyles: function() {
        return useContentStyles;
    },
    useIconStyles: function() {
        return useIconStyles;
    },
    useIndicatorStyles: function() {
        return useIndicatorStyles;
    },
    useRootDefaultClassName: function() {
        return useRootDefaultClassName;
    },
    useSmallStyles: function() {
        return useSmallStyles;
    }
});
const _reacticons = require("@fluentui/react-icons");
const _reacttheme = require("@fluentui/react-theme");
const _react = require("@griffel/react");
const navItemTokens = {
    defaultDrawerWidth: 260,
    indicatorOffset: 16,
    indicatorWidth: 4,
    indicatorHeight: 20,
    backgroundColor: _reacttheme.tokens.colorNeutralBackground4,
    backgroundColorHover: _reacttheme.tokens.colorNeutralBackground4Hover,
    backgroundColorPressed: _reacttheme.tokens.colorNeutralBackground4Pressed,
    animationTokens: {
        animationDuration: _reacttheme.tokens.durationFaster,
        animationFillMode: 'both',
        animationTimingFunction: _reacttheme.tokens.curveLinear
    },
    transitionTokens: {
        transitionDuration: _reacttheme.tokens.durationFaster,
        transitionTimingFunction: _reacttheme.tokens.curveLinear,
        transitionProperty: 'background'
    }
};
const useRootDefaultClassName = (0, _react.makeResetStyles)({
    display: 'flex',
    textTransform: 'none',
    position: 'relative',
    justifyContent: 'start',
    alignItems: 'flex-start',
    textAlign: 'left',
    gap: _reacttheme.tokens.spacingVerticalL,
    padding: `${_reacttheme.tokens.spacingVerticalMNudge} ${_reacttheme.tokens.spacingHorizontalS} ${_reacttheme.tokens.spacingVerticalMNudge} ${_reacttheme.tokens.spacingHorizontalMNudge}`,
    backgroundColor: navItemTokens.backgroundColor,
    borderRadius: _reacttheme.tokens.borderRadiusMedium,
    color: _reacttheme.tokens.colorNeutralForeground2,
    textDecorationLine: 'none',
    border: 'none',
    // this element can change between a button and an anchor
    // so we need to reset box sizing to prevent horizontal overflow
    boxSizing: 'border-box',
    cursor: 'pointer',
    transitionDuration: navItemTokens.animationTokens.animationDuration,
    transitionTimingFunction: navItemTokens.animationTokens.animationTimingFunction,
    transitionProperty: 'background',
    width: '100%',
    ..._reacttheme.typographyStyles.body1,
    ':hover': {
        backgroundColor: navItemTokens.backgroundColorHover
    },
    // Use custom insert focus indicator
    '&:focus-visible': {
        outline: `${_reacttheme.tokens.strokeWidthThick} solid ${_reacttheme.tokens.colorStrokeFocus2}`,
        outlineOffset: `calc(${_reacttheme.tokens.strokeWidthThick} * -1)`
    }
});
const useSmallStyles = (0, _react.makeStyles)({
    root: {
        padding: `${_reacttheme.tokens.spacingVerticalXS} ${_reacttheme.tokens.spacingHorizontalS} ${_reacttheme.tokens.spacingVerticalXS} ${_reacttheme.tokens.spacingHorizontalMNudge}`
    }
});
const useContentStyles = (0, _react.makeStyles)({
    selected: _reacttheme.typographyStyles.body1Strong
});
const useIndicatorStyles = (0, _react.makeStyles)({
    base: {
        '::after': {
            position: 'absolute',
            ...navItemTokens.animationTokens,
            animationName: {
                '0%': {
                    background: 'transparent'
                },
                '100%': {
                    background: _reacttheme.tokens.colorCompoundBrandForeground1
                }
            },
            marginInlineStart: `-${navItemTokens.indicatorOffset}px`,
            backgroundColor: _reacttheme.tokens.colorCompoundBrandForeground1,
            height: `${navItemTokens.indicatorHeight}px`,
            width: `${navItemTokens.indicatorWidth}px`,
            borderRadius: _reacttheme.tokens.borderRadiusCircular,
            content: '""'
        },
        '@media (forced-colors: active)': {
            '::after': {
                outline: `solid 2px ${_reacttheme.tokens.colorTransparentStroke}`,
                outlineOffset: '-2px'
            }
        }
    }
});
const useIconStyles = (0, _react.makeStyles)({
    base: {
        display: 'grid',
        gridTemplateAreas: 'overlay-area',
        minHeight: '20px',
        minWidth: '20px',
        alignItems: 'top',
        justifyContent: 'center',
        overflow: 'hidden',
        [`& .${_reacticons.iconFilledClassName}`]: {
            gridArea: 'overlay-area',
            color: 'transparent',
            display: 'none'
        },
        [`& .${_reacticons.iconRegularClassName}`]: {
            gridArea: 'overlay-area',
            display: 'inline'
        }
    },
    selected: {
        [`& .${_reacticons.iconFilledClassName}`]: {
            ...navItemTokens.animationTokens,
            display: 'inline',
            animationName: {
                '0%': {
                    opacity: 0,
                    color: 'transparent'
                },
                '100%': {
                    opacity: 1,
                    color: _reacttheme.tokens.colorNeutralForeground2BrandSelected
                }
            }
        },
        [`& .${_reacticons.iconRegularClassName}`]: {
            ...navItemTokens.animationTokens,
            animationName: {
                '0%': {
                    opacity: 1,
                    color: _reacttheme.tokens.colorNeutralForeground2
                },
                '100%': {
                    opacity: 0,
                    color: 'transparent'
                }
            }
        }
    }
});
