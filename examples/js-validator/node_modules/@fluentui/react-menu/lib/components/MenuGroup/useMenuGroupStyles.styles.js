import { mergeClasses } from '@griffel/react';
export const menuGroupClassNames = {
  root: 'fui-MenuGroup'
};
export const useMenuGroupStyles_unstable = state => {
  'use no memo';

  state.root.className = mergeClasses(menuGroupClassNames.root, state.root.className);
  return state;
};