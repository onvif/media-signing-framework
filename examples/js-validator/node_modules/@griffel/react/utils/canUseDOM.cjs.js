'use strict';

/**
 * Verifies if an application can use DOM.
 */
function canUseDOM() {
  return typeof window !== 'undefined' && !!(window.document && window.document.createElement);
}

exports.canUseDOM = canUseDOM;
//# sourceMappingURL=canUseDOM.cjs.js.map
