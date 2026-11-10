'use strict';

require('./constants.cjs.js');
var store = require('./devtools/store.cjs.js');
var isDevToolsEnabled = require('./devtools/isDevToolsEnabled.cjs.js');
var getSourceURLfromError = require('./devtools/getSourceURLfromError.cjs.js');
var insertionFactory = require('./insertionFactory.cjs.js');
var resolveStyleRulesForSlots = require('./resolveStyleRulesForSlots.cjs.js');
var reduceToClassNameForSlots = require('./runtime/reduceToClassNameForSlots.cjs.js');

function makeStyles(stylesBySlots, factory = insertionFactory.insertionFactory) {
  const insertStyles = factory();
  let classesMapBySlot = null;
  let cssRules = null;
  let ltrClassNamesForSlots = null;
  let rtlClassNamesForSlots = null;
  let sourceURL;
  if (process.env.NODE_ENV !== 'production' && isDevToolsEnabled.isDevToolsEnabled) {
    sourceURL = getSourceURLfromError.getSourceURLfromError();
  }
  let classNameHashSalt;
  function computeClasses(options) {
    const {
      dir,
      renderer
    } = options;
    if (classesMapBySlot === null) {
      [classesMapBySlot, cssRules] = resolveStyleRulesForSlots.resolveStyleRulesForSlots(stylesBySlots, renderer.classNameHashSalt);
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
        ltrClassNamesForSlots = reduceToClassNameForSlots.reduceToClassNameForSlots(classesMapBySlot, dir);
      }
    } else {
      if (rtlClassNamesForSlots === null) {
        rtlClassNamesForSlots = reduceToClassNameForSlots.reduceToClassNameForSlots(classesMapBySlot, dir);
      }
    }
    insertStyles(renderer, cssRules);
    const classNamesForSlots = isLTR ? ltrClassNamesForSlots : rtlClassNamesForSlots;
    if (process.env.NODE_ENV !== 'production' && isDevToolsEnabled.isDevToolsEnabled) {
      store.debugData.addSequenceDetails(classNamesForSlots, sourceURL);
    }
    return classNamesForSlots;
  }
  return computeClasses;
}

exports.makeStyles = makeStyles;
//# sourceMappingURL=makeStyles.cjs.js.map
