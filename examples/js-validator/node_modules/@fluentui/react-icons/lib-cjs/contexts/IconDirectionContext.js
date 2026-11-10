"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useIconContext = exports.IconDirectionContextProvider = void 0;
const tslib_1 = require("tslib");
const React = tslib_1.__importStar(require("react"));
const IconDirectionContext = React.createContext(undefined);
const IconDirectionContextDefaultValue = {};
exports.IconDirectionContextProvider = IconDirectionContext.Provider;
const useIconContext = () => {
    const context = React.useContext(IconDirectionContext);
    return context !== null && context !== void 0 ? context : IconDirectionContextDefaultValue;
};
exports.useIconContext = useIconContext;
