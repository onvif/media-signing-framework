import * as React from "react";
import { mergeClasses } from "@griffel/react";
import { useIconState } from "./useIconState";
import { useRootStyles } from "./createFluentIcon.styles";
export const createFluentIcon = (displayName, width, pathsOrSvg, options) => {
    const viewBoxWidth = width === "1em" ? "20" : width;
    const Icon = React.forwardRef((props, ref) => {
        const styles = useRootStyles();
        const iconState = useIconState(props, { flipInRtl: options === null || options === void 0 ? void 0 : options.flipInRtl }); // HTML attributes/props for things like accessibility can be passed in, and will be expanded on the svg object at the start of the object
        const state = {
            ...iconState,
            className: mergeClasses(iconState.className, styles.root),
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
