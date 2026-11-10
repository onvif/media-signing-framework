'use strict';

/**
 * A function that implements CSS spec conformant expansion for "margin-block"
 *
 * @example
 *   marginBlock('10px')
 *   marginBlock('10px', '5px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/margin-block
 *
 * @deprecated Just use `{ marginBlock: '10px' }` instead as Griffel supports CSS shorthands now
 */
function marginBlock(start, end = start) {
  return {
    marginBlockStart: start,
    marginBlockEnd: end
  };
}

exports.marginBlock = marginBlock;
//# sourceMappingURL=marginBlock.cjs.js.map
