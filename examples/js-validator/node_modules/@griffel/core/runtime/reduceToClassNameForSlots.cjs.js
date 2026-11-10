'use strict';

var constants = require('../constants.cjs.js');
var hashSequence = require('./utils/hashSequence.cjs.js');

/**
 * Reduces a classname map for slot to a classname string. Uses classnames according to text directions.
 *
 * @private
 */
function reduceToClassName(classMap, dir) {
  // - `classString` is a string of classnames separated by a space, used to output classes
  // - `hashString` is a string of classnames separated by a space, used to generate a hash
  //
  // `hashString` is needed to handle `null` values in a class map as they don't produce any classes.
  let classString = '';
  let hashString = '';
  // eslint-disable-next-line guard-for-in
  for (const propertyHash in classMap) {
    const classNameMapping = classMap[propertyHash];
    if (classNameMapping === 0) {
      hashString += propertyHash + ' ';
      continue;
    }
    const hasRTLClassName = Array.isArray(classNameMapping);
    const className = dir === 'rtl' ? (hasRTLClassName ? classNameMapping[1] : classNameMapping) + ' ' : (hasRTLClassName ? classNameMapping[0] : classNameMapping) + ' ';
    classString += className;
    hashString += className;
  }
  return [classString.slice(0, -1), hashString.slice(0, -1)];
}
/**
 * Reduces classname maps for slots to classname strings. Registers them in a definition cache to be used by
 * `mergeClasses()`.
 *
 * @internal
 */
function reduceToClassNameForSlots(classesMapBySlot, dir) {
  const classNamesForSlots = {};
  // eslint-disable-next-line guard-for-in
  for (const slotName in classesMapBySlot) {
    const [slotClasses, slotClassesHash] = reduceToClassName(classesMapBySlot[slotName], dir);
    // Handles a case when there are no classes in a set i.e. "makeStyles({ root: {} })"
    if (slotClassesHash === '') {
      classNamesForSlots[slotName] = '';
      continue;
    }
    const sequenceHash = hashSequence.hashSequence(slotClassesHash, dir);
    const resultSlotClasses = sequenceHash + (slotClasses === '' ? '' : ' ' + slotClasses);
    constants.DEFINITION_LOOKUP_TABLE[sequenceHash] = [classesMapBySlot[slotName], dir];
    classNamesForSlots[slotName] = resultSlotClasses;
  }
  return classNamesForSlots;
}

exports.reduceToClassName = reduceToClassName;
exports.reduceToClassNameForSlots = reduceToClassNameForSlots;
//# sourceMappingURL=reduceToClassNameForSlots.cjs.js.map
