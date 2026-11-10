"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useRootStyles = exports.useStaticStyles = void 0;
const tslib_1 = require("tslib");
const react_1 = require("@griffel/react");
const FluentSystemIcons_Filled_ttf_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Filled.ttf"));
const FluentSystemIcons_Filled_woff_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Filled.woff"));
const FluentSystemIcons_Filled_woff2_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Filled.woff2"));
const FluentSystemIcons_Regular_ttf_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Regular.ttf"));
const FluentSystemIcons_Regular_woff_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Regular.woff"));
const FluentSystemIcons_Regular_woff2_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Regular.woff2"));
const FluentSystemIcons_Light_ttf_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Light.ttf"));
const FluentSystemIcons_Light_woff_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Light.woff"));
const FluentSystemIcons_Light_woff2_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Light.woff2"));
const FluentSystemIcons_Resizable_ttf_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Resizable.ttf"));
const FluentSystemIcons_Resizable_woff_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Resizable.woff"));
const FluentSystemIcons_Resizable_woff2_1 = tslib_1.__importDefault(require("./FluentSystemIcons-Resizable.woff2"));
const FONT_FAMILY_MAP = {
    [0 /* Filled */]: 'FluentSystemIconsFilled',
    [1 /* Regular */]: 'FluentSystemIconsRegular',
    [2 /* Resizable */]: 'FluentSystemIcons',
};
exports.useStaticStyles = react_1.makeStaticStyles(`
@font-face {
    font-family: ${FONT_FAMILY_MAP[0 /* Filled */]};
    font-display: "block";
    src: url(${JSON.stringify(FluentSystemIcons_Filled_woff2_1.default)}) format("woff2"),
    url(${JSON.stringify(FluentSystemIcons_Filled_woff_1.default)}) format("woff"),
    url(${JSON.stringify(FluentSystemIcons_Filled_ttf_1.default)}) format("truetype");
}
@font-face {
    font-family: ${FONT_FAMILY_MAP[1 /* Regular */]};
    font-display: "block";
    src: url(${JSON.stringify(FluentSystemIcons_Regular_woff2_1.default)}) format("woff2"),
    url(${JSON.stringify(FluentSystemIcons_Regular_woff_1.default)}) format("woff"),
    url(${JSON.stringify(FluentSystemIcons_Regular_ttf_1.default)}) format("truetype");
}

@font-face {
    font-family: ${FONT_FAMILY_MAP[3 /* Light */]};
    src: url(${JSON.stringify(FluentSystemIcons_Light_woff2_1.default)}) format("woff2"),
    url(${JSON.stringify(FluentSystemIcons_Light_woff_1.default)}) format("woff"),
    url(${JSON.stringify(FluentSystemIcons_Light_ttf_1.default)}) format("truetype");
}

@font-face {
    font-family: ${FONT_FAMILY_MAP[2 /* Resizable */]};
    font-display: "block";
    src: url(${JSON.stringify(FluentSystemIcons_Resizable_woff2_1.default)}) format("woff2"),
    url(${JSON.stringify(FluentSystemIcons_Resizable_woff_1.default)}) format("woff"),
    url(${JSON.stringify(FluentSystemIcons_Resizable_ttf_1.default)}) format("truetype");
}
`);
exports.useRootStyles = react_1.makeStyles({
    root: {
        display: 'inline-block',
        fontStyle: 'normal',
        lineHeight: '1em',
        color: 'currentColor',
    },
    [0 /* Filled */]: {
        fontFamily: 'FluentSystemIconsFilled',
    },
    [1 /* Regular */]: {
        fontFamily: 'FluentSystemIconsRegular',
    },
    [2 /* Resizable */]: {
        fontFamily: 'FluentSystemIcons',
    },
    [3 /* Light */]: {
        fontFamily: 'FluentSystemIconsLight',
    }
});
