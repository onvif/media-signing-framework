/**
 * Calculate the role for the list based on the navigation mode and selectable state
 * @param navigationMode - the navigation mode of the list
 * @param selectable - whether the list is selectable
 * @returns 'grid' if navigationMode is 'composite', otherwise 'listbox' if selectable or 'list' if not
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "calculateListRole", {
    enumerable: true,
    get: function() {
        return calculateListRole;
    }
});
const calculateListRole = (navigationMode, selectable)=>{
    if (navigationMode === 'composite') {
        return 'grid';
    } else if (selectable) {
        return 'listbox';
    } else {
        return 'list';
    }
};
