'use strict';

var utils = require('./utils.cjs.js');

/**
 * A function that implements expansion for "border-left", it's simplified - check usage examples.
 *
 * @example
 *  borderLeft('2px')
 *  borderLeft('solid')
 *  borderLeft('2px', 'solid')
 *  borderLeft('solid', '2px')
 *  borderLeft('2px', 'solid', 'red')
 *  borderLeft('solid', '2px', 'red')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/border-left
 *
 * @deprecated Just use `{ borderLeft: '2px solid red' }` instead as Griffel supports CSS shorthands now
 */
function borderLeft(...values) {
  if (utils.isBorderStyle(values[0])) {
    return Object.assign({
      borderLeftStyle: values[0]
    }, values[1] && {
      borderLeftWidth: values[1]
    }, values[2] && {
      borderLeftColor: values[2]
    });
  }
  return Object.assign({
    borderLeftWidth: values[0]
  }, values[1] && {
    borderLeftStyle: values[1]
  }, values[2] && {
    borderLeftColor: values[2]
  });
}

exports.borderLeft = borderLeft;
//# sourceMappingURL=borderLeft.cjs.js.map
