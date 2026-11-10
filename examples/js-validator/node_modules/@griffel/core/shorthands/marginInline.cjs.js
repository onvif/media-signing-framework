'use strict';

/**
 * A function that implements CSS spec conformant expansion for "margin-inline"
 *
 * @example
 *   marginInline('10px')
 *   marginInline('10px', '5px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/margin-inline
 *
 * @deprecated Just use `{ marginInline: '10px' }` instead as Griffel supports CSS shorthands now
 */
function marginInline(start, end = start) {
  return {
    marginInlineStart: start,
    marginInlineEnd: end
  };
}

exports.marginInline = marginInline;
//# sourceMappingURL=marginInline.cjs.js.map
