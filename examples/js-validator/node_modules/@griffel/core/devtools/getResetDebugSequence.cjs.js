'use strict';

var constants = require('../constants.cjs.js');
var store = require('./store.cjs.js');

function getResetDebugSequence(debugSequenceHash) {
  const resetClass = constants.DEBUG_RESET_CLASSES[debugSequenceHash];
  if (resetClass === undefined) {
    return undefined;
  }
  const debugClassNames = [{
    className: debugSequenceHash
  }];
  const node = {
    sequenceHash: debugSequenceHash,
    direction: 'ltr',
    children: [],
    debugClassNames
  };
  node.rules = {};
  node.slot = 'makeResetStyles()';
  const [{
    className
  }] = node.debugClassNames;
  const cssRules = store.debugData.getCSSRules().filter(cssRule => {
    return cssRule.includes(`.${className}`);
  });
  node.rules[className] = cssRules.join('');
  return node;
}

exports.getResetDebugSequence = getResetDebugSequence;
//# sourceMappingURL=getResetDebugSequence.cjs.js.map
