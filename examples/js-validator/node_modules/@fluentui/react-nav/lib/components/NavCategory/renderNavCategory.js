import * as React from 'react';
import { NavCategoryProvider } from '../NavCategoryContext';
/**
 * Render the final JSX of NavCategory
 */ export const renderNavCategory_unstable = (state, contextValues)=>{
    return /*#__PURE__*/ React.createElement(NavCategoryProvider, {
        value: contextValues.categoryValue
    }, state.children);
};
