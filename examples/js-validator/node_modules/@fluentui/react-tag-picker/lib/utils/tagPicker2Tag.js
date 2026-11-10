export function tagPickerSizeToTagSize(size) {
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
export function tagSizeToTagPickerSize(size) {
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
export function tagPickerAppearanceToTagAppearance(appearance) {
    switch(appearance){
        case 'filled-darker':
            return 'outline';
        default:
            return 'filled';
    }
}
