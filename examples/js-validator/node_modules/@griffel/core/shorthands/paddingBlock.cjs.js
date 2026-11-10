'use strict';

/**
 * A function that implements CSS spec conformant expansion for "padding-block"
 *
 * @example
 *   paddingBlock('10px')
 *   paddingBlock('10px', '5px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/padding-block
 *
 * @deprecated Just use `{ paddingBlock: '10px' }` instead as Griffel supports CSS shorthands now
 */
function paddingBlock(start, end = start) {
  return {
    paddingBlockStart: start,
    paddingBlockEnd: end
  };
}

exports.paddingBlock = paddingBlock;
//# sourceMappingURL=paddingBlock.cjs.js.map
