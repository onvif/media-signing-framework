'use strict';

var utils = require('./utils.cjs.js');

/**
 * A function that implements expansion for "border-Top", it's simplified - check usage examples.
 *
 * @example
 *  borderTop('2px')
 *  borderTop('solid')
 *  borderTop('2px', 'solid')
 *  borderTop('solid', '2px')
 *  borderTop('2px', 'solid', 'red')
 *  borderTop('solid', '2px', 'red')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/border-top
 *
 * @deprecated Just use `{ borderTop: '2px solid red' }` instead as Griffel supports CSS shorthands now
 */
function borderTop(...values) {
  if (utils.isBorderStyle(values[0])) {
    return Object.assign({
      borderTopStyle: values[0]
    }, values[1] && {
      borderTopWidth: values[1]
    }, values[2] && {
      borderTopColor: values[2]
    });
  }
  return Object.assign({
    borderTopWidth: values[0]
  }, values[1] && {
    borderTopStyle: values[1]
  }, values[2] && {
    borderTopColor: values[2]
  });
}

exports.borderTop = borderTop;
//# sourceMappingURL=borderTop.cjs.js.map
