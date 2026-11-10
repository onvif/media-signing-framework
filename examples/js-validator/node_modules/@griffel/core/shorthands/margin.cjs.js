'use strict';

var generateStyles = require('./generateStyles.cjs.js');

/**
 * A function that implements CSS spec conformant expansion for "margin"
 *
 * @example
 *   margin('10px')
 *   margin('10px', '5px')
 *   margin('2px', '4px', '8px')
 *   margin('1px', 0, '3px', '4px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/margin
 *
 * @deprecated Just use `{ margin: '10px 5px 8px 4px' }` instead as Griffel supports CSS shorthands now
 */
function margin(...values) {
  return generateStyles.generateStyles('margin', '', ...values);
}

exports.margin = margin;
//# sourceMappingURL=margin.cjs.js.map
