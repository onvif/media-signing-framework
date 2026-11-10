"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useStyles = void 0;
const react_1 = require("@griffel/react");
exports.useStyles = react_1.makeStyles({
    root: {
        display: 'inline',
        lineHeight: 0
    },
    rtl: {
        transform: 'scaleX(-1)'
    }
});
