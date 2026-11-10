import { renderTagGroup_unstable } from '@fluentui/react-tags';
export function renderTagPickerGroup_unstable(state, contexts) {
    if (!state.hasSelectedOptions) {
        return null;
    }
    return renderTagGroup_unstable(state, contexts);
}
