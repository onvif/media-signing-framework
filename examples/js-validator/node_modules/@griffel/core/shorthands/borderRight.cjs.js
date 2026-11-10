'use strict';

var utils = require('./utils.cjs.js');

/**
 * A function that implements expansion for "border-right", it's simplified - check usage examples.
 *
 * @example
 *  borderRight('2px')
 *  borderRight('solid')
 *  borderRight('2px', 'solid')
 *  borderRight('solid', '2px')
 *  borderRight('2px', 'solid', 'red')
 *  borderRight('solid', '2px', 'red')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/border-right
 *
 * @deprecated Just use `{ borderRight: '2px solid red' }` instead as Griffel supports CSS shorthands now
 */
function borderRight(...values) {
  if (utils.isBorderStyle(values[0])) {
    return Object.assign({
      borderRightStyle: values[0]
    }, values[1] && {
      borderRightWidth: values[1]
    }, values[2] && {
      borderRightColor: values[2]
    });
  }
  return Object.assign({
    borderRightWidth: values[0]
  }, values[1] && {
    borderRightStyle: values[1]
  }, values[2] && {
    borderRightColor: values[2]
  });
}

exports.borderRight = borderRight;
//# sourceMappingURL=borderRight.cjs.js.map
