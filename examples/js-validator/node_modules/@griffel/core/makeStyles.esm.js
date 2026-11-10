import './constants.esm.js';
import { debugData } from './devtools/store.esm.js';
import { isDevToolsEnabled } from './devtools/isDevToolsEnabled.esm.js';
import { getSourceURLfromError } from './devtools/getSourceURLfromError.esm.js';
import { insertionFactory } from './insertionFactory.esm.js';
import { resolveStyleRulesForSlots } from './resolveStyleRulesForSlots.esm.js';
import { reduceToClassNameForSlots } from './runtime/reduceToClassNameForSlots.esm.js';

function makeStyles(stylesBySlots, factory = insertionFactory) {
  const insertStyles = factory();
  let classesMapBySlot = null;
  let cssRules = null;
  let ltrClassNamesForSlots = null;
  let rtlClassNamesForSlots = null;
  let sourceURL;
  if (process.env.NODE_ENV !== 'production' && isDevToolsEnabled) {
    sourceURL = getSourceURLfromError();
  }
  let classNameHashSalt;
  function computeClasses(options) {
    const {
      dir,
      renderer
    } = options;
    if (classesMapBySlot === null) {
      [classesMapBySlot, cssRules] = resolveStyleRulesForSlots(stylesBySlots, renderer.classNameHashSalt);
      if (process.env.NODE_ENV !== 'production') {
        if (renderer.classNameHashSalt) {
          if (classNameHashSalt !== renderer.classNameHashSalt) {
            console.error(['@griffel/core:', '\n\n', 'A provided renderer has different "classNameHashSalt".', 'This is not supported and WILL cause issues with classnames generation.', 'Ensure that all renderers created with "createDOMRenderer()" have the same "classNameHashSalt".'].join(' '));
          }
          classNameHashSalt = renderer.classNameHashSalt;
        }
      }
    }
    const isLTR = dir === 'ltr';
    if (isLTR) {
      if (ltrClassNamesForSlots === null) {
        ltrClassNamesForSlots = reduceToClassNameForSlots(classesMapBySlot, dir);
      }
    } else {
      if (rtlClassNamesForSlots === null) {
        rtlClassNamesForSlots = reduceToClassNameForSlots(classesMapBySlot, dir);
      }
    }
    insertStyles(renderer, cssRules);
    const classNamesForSlots = isLTR ? ltrClassNamesForSlots : rtlClassNamesForSlots;
    if (process.env.NODE_ENV !== 'production' && isDevToolsEnabled) {
      debugData.addSequenceDetails(classNamesForSlots, sourceURL);
    }
    return classNamesForSlots;
  }
  return computeClasses;
}

export { makeStyles };
//# sourceMappingURL=makeStyles.esm.js.map
