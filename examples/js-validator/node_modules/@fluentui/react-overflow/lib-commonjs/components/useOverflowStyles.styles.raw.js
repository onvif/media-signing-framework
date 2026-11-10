"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useOverflowStyles", {
    enumerable: true,
    get: function() {
        return useOverflowStyles;
    }
});
const _react = require("@griffel/react");
const _constants = require("../constants");
const useOverflowStyles = (0, _react.makeStyles)({
    overflowMenu: {
        [`& [${_constants.DATA_OVERFLOW_MENU}]`]: {
            flexShrink: 0
        }
    },
    overflowingItems: {
        [`& [${_constants.DATA_OVERFLOWING}]`]: {
            display: 'none'
        }
    }
});
