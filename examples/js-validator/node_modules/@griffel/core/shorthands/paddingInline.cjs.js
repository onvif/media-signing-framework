'use strict';

/**
 * A function that implements CSS spec conformant expansion for "padding-inline"
 *
 * @example
 *   paddingInline('10px')
 *   paddingInline('10px', '5px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/padding-inline
 *
 * @deprecated Just use `{ paddingInline: '10px' }` instead as Griffel supports CSS shorthands now
 */
function paddingInline(start, end = start) {
  return {
    paddingInlineStart: start,
    paddingInlineEnd: end
  };
}

exports.paddingInline = paddingInline;
//# sourceMappingURL=paddingInline.cjs.js.map
