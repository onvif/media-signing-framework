'use strict';

/**
 * Trims selectors to generate consistent hashes.
 */
function trimSelector(selector) {
  return selector.replace(/>\s+/g, '>');
}

exports.trimSelector = trimSelector;
//# sourceMappingURL=trimSelector.cjs.js.map
