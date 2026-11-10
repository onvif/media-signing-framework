import hashString from '@emotion/hash';

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
  const hashedKey = hashString(computedKey);
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

export { atRulesToString, hashPropertyKey };
//# sourceMappingURL=hashPropertyKey.esm.js.map
