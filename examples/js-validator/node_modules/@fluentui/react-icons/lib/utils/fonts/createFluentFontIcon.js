import * as React from 'react';
import { mergeClasses } from "@griffel/react";
import { useIconState } from '../useIconState';
import { fontIconClassName } from '../constants';
import { useRootStyles, useStaticStyles } from './createFluentFontIcon.styles';
export function createFluentFontIcon(displayName, codepoint, font, fontSize, options) {
    const Component = (props) => {
        useStaticStyles();
        const styles = useRootStyles();
        const className = mergeClasses(styles.root, styles[font], fontIconClassName, props.className);
        const state = useIconState({ ...props, className }, { flipInRtl: options === null || options === void 0 ? void 0 : options.flipInRtl });
        // We want to keep the same API surface as the SVG icons, so translate `primaryFill` to `color`
        if (props.primaryFill && props.primaryFill.toLowerCase() !== 'currentcolor') {
            state.style = {
                ...state.style,
                color: props.primaryFill
            };
        }
        if (fontSize) {
            state.style = {
                ...state.style,
                fontSize
            };
        }
        return React.createElement("i", Object.assign({}, state), codepoint);
    };
    Component.displayName = displayName;
    Component.codepoint = codepoint;
    return Component;
}
