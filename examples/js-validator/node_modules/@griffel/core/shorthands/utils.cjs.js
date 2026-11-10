'use strict';

const LINE_STYLES = ['none', 'hidden', 'dotted', 'dashed', 'solid', 'double', 'groove', 'ridge', 'inset', 'outset'];
function isBorderStyle(value) {
  return LINE_STYLES.includes(value);
}

exports.isBorderStyle = isBorderStyle;
//# sourceMappingURL=utils.cjs.js.map
