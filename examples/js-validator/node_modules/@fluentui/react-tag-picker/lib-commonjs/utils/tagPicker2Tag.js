"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    tagPickerAppearanceToTagAppearance: function() {
        return tagPickerAppearanceToTagAppearance;
    },
    tagPickerSizeToTagSize: function() {
        return tagPickerSizeToTagSize;
    },
    tagSizeToTagPickerSize: function() {
        return tagSizeToTagPickerSize;
    }
});
function tagPickerSizeToTagSize(size) {
    switch(size){
        case 'medium':
            return 'extra-small';
        case 'large':
            return 'small';
        case 'extra-large':
            return 'medium';
        default:
            return 'extra-small';
    }
}
function tagSizeToTagPickerSize(size) {
    switch(size){
        case 'extra-small':
            return 'medium';
        case 'small':
            return 'large';
        case 'medium':
            return 'extra-large';
        default:
            return 'medium';
    }
}
function tagPickerAppearanceToTagAppearance(appearance) {
    switch(appearance){
        case 'filled-darker':
            return 'outline';
        default:
            return 'filled';
    }
}
