/**
 * Validates that the List and ListItem elements are compatible
 * @param listRenderedAs - the type of the parent element
 * @param listItemRenderedAs - the type of the child element
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "validateProperElementTypes", {
    enumerable: true,
    get: function() {
        return validateProperElementTypes;
    }
});
function validateProperElementTypes(listRenderedAs, listItemRenderedAs) {
    if (listItemRenderedAs === 'div' && listRenderedAs !== 'div') {
        throw new Error('ListItem cannot be rendered as a div when its parent is not a div.');
    }
    if (listItemRenderedAs === 'li' && listRenderedAs === 'div') {
        throw new Error('ListItem cannot be rendered as a li when its parent is a div.');
    }
}
