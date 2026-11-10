'use strict';

const regex = /^(:|\[|>|&)/;
function isNestedSelector(property) {
  return regex.test(property);
}

exports.isNestedSelector = isNestedSelector;
//# sourceMappingURL=isNestedSelector.cjs.js.map
