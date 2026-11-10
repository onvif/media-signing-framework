/**
 * A function that implements CSS spec conformant expansion for "gap"
 *
 * @example
 *   gap('10px')
 *   gap('10px', '5px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/gap
 *
 * @deprecated Just use `{ gap: '10px 5px' }` instead as Griffel supports CSS shorthands now
 */
function gap(columnGap, rowGap = columnGap) {
  return {
    columnGap,
    rowGap
  };
}

export { gap };
//# sourceMappingURL=gap.esm.js.map
