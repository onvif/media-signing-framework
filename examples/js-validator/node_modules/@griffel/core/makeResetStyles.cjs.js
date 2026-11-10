'use strict';

var constants = require('./constants.cjs.js');
var insertionFactory = require('./insertionFactory.cjs.js');
var resolveResetStyleRules = require('./runtime/resolveResetStyleRules.cjs.js');

function makeResetStyles(styles, factory = insertionFactory.insertionFactory) {
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
      [ltrClassName, rtlClassName, cssRules] = resolveResetStyleRules.resolveResetStyleRules(styles, renderer.classNameHashSalt);
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
      constants.DEBUG_RESET_CLASSES[className] = 1;
    }
    return className;
  }
  return computeClassName;
}

exports.makeResetStyles = makeResetStyles;
//# sourceMappingURL=makeResetStyles.cjs.js.map
