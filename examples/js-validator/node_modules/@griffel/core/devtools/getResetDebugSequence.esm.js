import { DEBUG_RESET_CLASSES } from '../constants.esm.js';
import { debugData } from './store.esm.js';

function getResetDebugSequence(debugSequenceHash) {
  const resetClass = DEBUG_RESET_CLASSES[debugSequenceHash];
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
  const cssRules = debugData.getCSSRules().filter(cssRule => {
    return cssRule.includes(`.${className}`);
  });
  node.rules[className] = cssRules.join('');
  return node;
}

export { getResetDebugSequence };
//# sourceMappingURL=getResetDebugSequence.esm.js.map
