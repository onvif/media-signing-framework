/**
 * A function that implements CSS spec conformant expansion for "overflow"
 *
 * @example
 *   overflow('hidden')
 *   overflow('hidden', 'scroll')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/overflow
 *
 * @deprecated Just use `{ overflow: 'hidden scroll' }` instead as Griffel supports CSS shorthands now
 */
function overflow(overflowX, overflowY = overflowX) {
  return {
    overflowX,
    overflowY
  };
}

export { overflow };
//# sourceMappingURL=overflow.esm.js.map
