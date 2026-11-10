'use strict';

var resolveStyleRules = require('./runtime/resolveStyleRules.cjs.js');

/**
 * Calls resolveStyleRules() for each slot, is also used by build time transform.
 *
 * @param stylesBySlots - An object with makeStyles rules where a key is a slot name
 * @param classNameHashSalt - A salt for classes hash
 *
 * @return - A tuple with an object classnames mapping where a key is a slot name and an array with CSS rules
 */
function resolveStyleRulesForSlots(stylesBySlots, classNameHashSalt = '') {
  const classesMapBySlot = {};
  const cssRules = {};
  // eslint-disable-next-line guard-for-in
  for (const slotName in stylesBySlots) {
    const slotStyles = stylesBySlots[slotName];
    const [cssClassMap, cssRulesByBucket] = resolveStyleRules.resolveStyleRules(slotStyles, classNameHashSalt);
    classesMapBySlot[slotName] = cssClassMap;
    Object.keys(cssRulesByBucket).forEach(styleBucketName => {
      cssRules[styleBucketName] = (cssRules[styleBucketName] || []).concat(cssRulesByBucket[styleBucketName]);
    });
  }
  return [classesMapBySlot, cssRules];
}

exports.resolveStyleRulesForSlots = resolveStyleRulesForSlots;
//# sourceMappingURL=resolveStyleRulesForSlots.cjs.js.map
