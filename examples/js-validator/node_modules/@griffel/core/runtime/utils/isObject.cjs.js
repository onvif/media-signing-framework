'use strict';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isObject(val) {
  return val != null && typeof val === 'object' && Array.isArray(val) === false;
}

exports.isObject = isObject;
//# sourceMappingURL=isObject.cjs.js.map
