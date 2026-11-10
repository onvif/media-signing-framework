/**
 * Calculate the role for the list item based on the list role.
 * @param listRole - the role of the list
 * @returns proper role for the list item
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "calculateListItemRoleForListRole", {
    enumerable: true,
    get: function() {
        return calculateListItemRoleForListRole;
    }
});
const calculateListItemRoleForListRole = (listRole)=>{
    switch(listRole){
        case 'list':
            return 'listitem';
        case 'listbox':
            return 'option';
        case 'grid':
            return 'row';
        default:
            return 'listitem';
    }
};
