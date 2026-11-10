"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useIconState = void 0;
const contexts_1 = require("../contexts");
const react_1 = require("@griffel/react");
const useIconStyles_styles_1 = require("./useIconStyles.styles");
const useIconState = (props, options) => {
    const { title, primaryFill = "currentColor", ...rest } = props;
    const state = {
        ...rest,
        title: undefined,
        fill: primaryFill
    };
    const styles = useIconStyles_styles_1.useStyles();
    const iconContext = contexts_1.useIconContext();
    state.className = react_1.mergeClasses(styles.root, (options === null || options === void 0 ? void 0 : options.flipInRtl) && (iconContext === null || iconContext === void 0 ? void 0 : iconContext.textDirection) === 'rtl' && styles.rtl, state.className);
    if (title) {
        state['aria-label'] = title;
    }
    if (!state['aria-label'] && !state['aria-labelledby']) {
        state['aria-hidden'] = true;
    }
    else {
        state['role'] = 'img';
    }
    return state;
};
exports.useIconState = useIconState;
