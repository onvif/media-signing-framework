"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createFluentIcon = void 0;
const tslib_1 = require("tslib");
const React = tslib_1.__importStar(require("react"));
const react_1 = require("@griffel/react");
const useIconState_1 = require("./useIconState");
const createFluentIcon_styles_1 = require("./createFluentIcon.styles");
const createFluentIcon = (displayName, width, pathsOrSvg, options) => {
    const viewBoxWidth = width === "1em" ? "20" : width;
    const Icon = React.forwardRef((props, ref) => {
        const styles = createFluentIcon_styles_1.useRootStyles();
        const iconState = useIconState_1.useIconState(props, { flipInRtl: options === null || options === void 0 ? void 0 : options.flipInRtl }); // HTML attributes/props for things like accessibility can be passed in, and will be expanded on the svg object at the start of the object
        const state = {
            ...iconState,
            className: react_1.mergeClasses(iconState.className, styles.root),
            ref,
            width, height: width, viewBox: `0 0 ${viewBoxWidth} ${viewBoxWidth}`, xmlns: "http://www.w3.org/2000/svg"
        };
        if (typeof pathsOrSvg === "string") {
            // Color icon: render raw SVG children
            return React.createElement("svg", { ...state, dangerouslySetInnerHTML: { __html: pathsOrSvg } });
        }
        else {
            // Non-color icon: render paths as before
            return React.createElement("svg", state, ...pathsOrSvg.map((d) => React.createElement("path", { d, fill: state.fill })));
        }
    });
    Icon.displayName = displayName;
    return Icon;
};
exports.createFluentIcon = createFluentIcon;
