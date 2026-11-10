'use strict';

var hashString = require('@emotion/hash');

function _interopDefaultCompat (e) { return e && typeof e === 'object' && 'default' in e ? e : { default: e }; }

var hashString__default = /*#__PURE__*/_interopDefaultCompat(hashString);

function addAtRulePrefix(atRule, prefix) {
  return atRule ? prefix + atRule : atRule;
}
function atRulesToString(atRules) {
  return addAtRulePrefix(atRules.container, 'c') + addAtRulePrefix(atRules.media, 'm') + addAtRulePrefix(atRules.layer, 'l') + addAtRulePrefix(atRules.supports, 's');
}
function hashPropertyKey(selector, property, atRules) {
  // uniq key based on property & selector, used for merging later
  const computedKey = selector + atRulesToString(atRules) + property;
  // "key" can be really long as it includes selectors, we use hashes to reduce sizes of keys
  // ".foo :hover" => "abcd"
  const hashedKey = hashString__default.default(computedKey);
  // As these hashes are used as object keys in build output we should avoid having numbers as a first character to
  // avoid having quotes:
  // {
  //   "1abc": {}, // we don't want this
  //   Aabc: {}, // no quotes
  // }
  const firstCharCode = hashedKey.charCodeAt(0);
  const startsWithNumber = firstCharCode >= 48 && firstCharCode <= 57;
  if (startsWithNumber) {
    return String.fromCharCode(firstCharCode + 17) + hashedKey.slice(1);
  }
  return hashedKey;
}

exports.atRulesToString = atRulesToString;
exports.hashPropertyKey = hashPropertyKey;
//# sourceMappingURL=hashPropertyKey.cjs.js.map
