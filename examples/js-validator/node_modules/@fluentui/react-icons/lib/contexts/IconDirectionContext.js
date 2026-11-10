import * as React from 'react';
const IconDirectionContext = React.createContext(undefined);
const IconDirectionContextDefaultValue = {};
export const IconDirectionContextProvider = IconDirectionContext.Provider;
export const useIconContext = () => {
    const context = React.useContext(IconDirectionContext);
    return context !== null && context !== void 0 ? context : IconDirectionContextDefaultValue;
};
