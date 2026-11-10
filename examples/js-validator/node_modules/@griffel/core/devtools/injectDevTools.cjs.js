'use strict';

var constants = require('../constants.cjs.js');
var mergeDebugSequence = require('./mergeDebugSequence.cjs.js');

function injectDevTools(document) {
  const window = document.defaultView;
  if (!window || window.__GRIFFEL_DEVTOOLS__) {
    return;
  }
  const devtools = {
    getInfo: element => {
      let rootDebugSequenceHash;
      let rootResetDebugClassName;
      for (const className of element.classList) {
        if (className.startsWith(constants.SEQUENCE_PREFIX)) {
          rootDebugSequenceHash = className;
        }
        if (constants.DEBUG_RESET_CLASSES[className]) {
          rootResetDebugClassName = className;
        }
      }
      return mergeDebugSequence.mergeDebugSequence(rootDebugSequenceHash, rootResetDebugClassName);
    }
  };
  Object.defineProperty(window, '__GRIFFEL_DEVTOOLS__', {
    configurable: false,
    enumerable: false,
    get() {
      return devtools;
    }
  });
}

exports.injectDevTools = injectDevTools;
//# sourceMappingURL=injectDevTools.cjs.js.map
