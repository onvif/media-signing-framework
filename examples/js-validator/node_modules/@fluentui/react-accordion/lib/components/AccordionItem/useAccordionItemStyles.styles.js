import { mergeClasses } from '@griffel/react';
export const accordionItemClassNames = {
  root: 'fui-AccordionItem'
};
export const useAccordionItemStyles_unstable = state => {
  'use no memo';

  state.root.className = mergeClasses(accordionItemClassNames.root, state.root.className);
  return state;
};