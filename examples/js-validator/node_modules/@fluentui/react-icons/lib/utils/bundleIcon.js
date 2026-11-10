import * as React from "react";
import { mergeClasses } from "@griffel/react";
import { iconFilledClassName, iconRegularClassName } from "./constants";
import { useBundledIconStyles } from "./bundleIcon.styles";
const bundleIcon = (FilledIcon, RegularIcon) => {
    const Component = (props) => {
        const { className, filled, ...rest } = props;
        const styles = useBundledIconStyles();
        return (React.createElement(React.Fragment, null,
            React.createElement(FilledIcon, Object.assign({}, rest, { className: mergeClasses(styles.root, filled && styles.visible, iconFilledClassName, className) })),
            React.createElement(RegularIcon, Object.assign({}, rest, { className: mergeClasses(styles.root, !filled && styles.visible, iconRegularClassName, className) }))));
    };
    Component.displayName = "CompoundIcon";
    return Component;
};
export default bundleIcon;
