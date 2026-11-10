'use strict';

var hyphenateProperty = require('./hyphenateProperty.cjs.js');

function cssifyObject(style) {
  let css = '';
  // eslint-disable-next-line guard-for-in
  for (const property in style) {
    const value = style[property];
    if (typeof value === 'string' || typeof value === 'number') {
      css += hyphenateProperty.hyphenateProperty(property) + ':' + value + ';';
      continue;
    }
    if (Array.isArray(value)) {
      for (const arrValue of value) {
        css += hyphenateProperty.hyphenateProperty(property) + ':' + arrValue + ';';
      }
    }
  }
  return css;
}

exports.cssifyObject = cssifyObject;
//# sourceMappingURL=cssifyObject.cjs.js.map
