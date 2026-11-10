'use strict';

var cssifyObject = require('./utils/cssifyObject.cjs.js');
var compileCSSRules = require('./compileCSSRules.cjs.js');

function compileStaticCSS(property, value) {
  const cssRule = `${property} {${cssifyObject.cssifyObject(value)}}`;
  return compileCSSRules.compileCSSRules(cssRule, false)[0];
}

exports.compileStaticCSS = compileStaticCSS;
//# sourceMappingURL=compileStaticCSS.cjs.js.map
