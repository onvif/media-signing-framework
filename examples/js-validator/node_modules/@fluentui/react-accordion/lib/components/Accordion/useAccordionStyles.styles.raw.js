import { mergeClasses } from '@griffel/react';
export const accordionClassNames = {
    root: 'fui-Accordion'
};
export const useAccordionStyles_unstable = (state)=>{
    'use no memo';
    state.root.className = mergeClasses(accordionClassNames.root, state.root.className);
    return state;
};
