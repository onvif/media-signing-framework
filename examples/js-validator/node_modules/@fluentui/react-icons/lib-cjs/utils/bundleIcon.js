"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const React = tslib_1.__importStar(require("react"));
const react_1 = require("@griffel/react");
const constants_1 = require("./constants");
const bundleIcon_styles_1 = require("./bundleIcon.styles");
const bundleIcon = (FilledIcon, RegularIcon) => {
    const Component = (props) => {
        const { className, filled, ...rest } = props;
        const styles = bundleIcon_styles_1.useBundledIconStyles();
        return (React.createElement(React.Fragment, null,
            React.createElement(FilledIcon, Object.assign({}, rest, { className: react_1.mergeClasses(styles.root, filled && styles.visible, constants_1.iconFilledClassName, className) })),
            React.createElement(RegularIcon, Object.assign({}, rest, { className: react_1.mergeClasses(styles.root, !filled && styles.visible, constants_1.iconRegularClassName, className) }))));
    };
    Component.displayName = "CompoundIcon";
    return Component;
};
exports.default = bundleIcon;
