import hashString from '@emotion/hash';
import { HASH_PREFIX } from '../../constants.esm.js';
import { atRulesToString } from './hashPropertyKey.esm.js';

function hashClassName({
  property,
  selector,
  salt,
  value
}, atRules) {
  return HASH_PREFIX + hashString(salt + selector + atRulesToString(atRules) + property +
  // Trimming of value is required to generate consistent hashes
  value.trim());
}

export { hashClassName };
//# sourceMappingURL=hashClassName.esm.js.map
