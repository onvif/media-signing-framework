import { DEBUG_RESET_CLASSES } from './constants.esm.js';
import { insertionFactory } from './insertionFactory.esm.js';
import { resolveResetStyleRules } from './runtime/resolveResetStyleRules.esm.js';

function makeResetStyles(styles, factory = insertionFactory) {
  const insertStyles = factory();
  let ltrClassName = null;
  let rtlClassName = null;
  let cssRules = null;
  let classNameHashSalt;
  function computeClassName(options) {
    const {
      dir,
      renderer
    } = options;
    if (ltrClassName === null) {
      [ltrClassName, rtlClassName, cssRules] = resolveResetStyleRules(styles, renderer.classNameHashSalt);
      if (process.env.NODE_ENV !== 'production') {
        if (renderer.classNameHashSalt) {
          if (classNameHashSalt !== renderer.classNameHashSalt) {
            console.error(['@griffel/core:', '\n\n', 'A provided renderer has different "classNameHashSalt".', 'This is not supported and WILL cause issues with classnames generation.', 'Ensure that all renderers created with "createDOMRenderer()" have the same "classNameHashSalt".'].join(' '));
          }
          classNameHashSalt = renderer.classNameHashSalt;
        }
      }
    }
    insertStyles(renderer, Array.isArray(cssRules) ? {
      r: cssRules
    } : cssRules);
    const className = dir === 'ltr' ? ltrClassName : rtlClassName || ltrClassName;
    if (process.env.NODE_ENV !== 'production') {
      DEBUG_RESET_CLASSES[className] = 1;
    }
    return className;
  }
  return computeClassName;
}

export { makeResetStyles };
//# sourceMappingURL=makeResetStyles.esm.js.map
