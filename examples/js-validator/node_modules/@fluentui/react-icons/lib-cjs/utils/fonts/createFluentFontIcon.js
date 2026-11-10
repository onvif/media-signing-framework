"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createFluentFontIcon = void 0;
const tslib_1 = require("tslib");
const React = tslib_1.__importStar(require("react"));
const react_1 = require("@griffel/react");
const useIconState_1 = require("../useIconState");
const constants_1 = require("../constants");
const createFluentFontIcon_styles_1 = require("./createFluentFontIcon.styles");
function createFluentFontIcon(displayName, codepoint, font, fontSize, options) {
    const Component = (props) => {
        createFluentFontIcon_styles_1.useStaticStyles();
        const styles = createFluentFontIcon_styles_1.useRootStyles();
        const className = react_1.mergeClasses(styles.root, styles[font], constants_1.fontIconClassName, props.className);
        const state = useIconState_1.useIconState({ ...props, className }, { flipInRtl: options === null || options === void 0 ? void 0 : options.flipInRtl });
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
exports.createFluentFontIcon = createFluentFontIcon;
