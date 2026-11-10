'use strict';

var hashString = require('@emotion/hash');
var constants = require('../../constants.cjs.js');
var hashPropertyKey = require('./hashPropertyKey.cjs.js');

function _interopDefaultCompat (e) { return e && typeof e === 'object' && 'default' in e ? e : { default: e }; }

var hashString__default = /*#__PURE__*/_interopDefaultCompat(hashString);

function hashClassName({
  property,
  selector,
  salt,
  value
}, atRules) {
  return constants.HASH_PREFIX + hashString__default.default(salt + selector + hashPropertyKey.atRulesToString(atRules) + property +
  // Trimming of value is required to generate consistent hashes
  value.trim());
}

exports.hashClassName = hashClassName;
//# sourceMappingURL=hashClassName.cjs.js.map
