import { SEQUENCE_PREFIX, DEBUG_RESET_CLASSES } from '../constants.esm.js';
import { mergeDebugSequence } from './mergeDebugSequence.esm.js';

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
        if (className.startsWith(SEQUENCE_PREFIX)) {
          rootDebugSequenceHash = className;
        }
        if (DEBUG_RESET_CLASSES[className]) {
          rootResetDebugClassName = className;
        }
      }
      return mergeDebugSequence(rootDebugSequenceHash, rootResetDebugClassName);
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

export { injectDevTools };
//# sourceMappingURL=injectDevTools.esm.js.map
