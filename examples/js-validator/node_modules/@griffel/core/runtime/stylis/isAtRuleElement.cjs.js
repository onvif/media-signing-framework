'use strict';

var stylis = require('stylis');

function isAtRuleElement(element) {
  switch (element.type) {
    case '@container':
    case stylis.MEDIA:
    case stylis.SUPPORTS:
    case stylis.LAYER:
      return true;
  }
  return false;
}

exports.isAtRuleElement = isAtRuleElement;
//# sourceMappingURL=isAtRuleElement.cjs.js.map
