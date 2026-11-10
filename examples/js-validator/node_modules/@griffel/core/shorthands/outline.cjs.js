'use strict';

/**
 * A function that implements expansion for "outline", it's simplified - check usage examples.
 *
 * @example
 *  outline('2px')
 *  outline('2px', 'solid')
 *  outline('2px', 'solid', 'red')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/outline
 *
 * @deprecated Just use `{ outline: '2px solid red' }` instead as Griffel supports CSS shorthands now
 */
function outline(outlineWidth, outlineStyle, outlineColor) {
  return Object.assign({
    outlineWidth
  }, outlineStyle && {
    outlineStyle
  }, outlineColor && {
    outlineColor
  });
}

exports.outline = outline;
//# sourceMappingURL=outline.cjs.js.map
