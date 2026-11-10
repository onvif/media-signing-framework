'use strict';

var getAtomicDebugSequenceTree = require('./getAtomicDebugSequenceTree.cjs.js');
var getResetDebugSequence = require('./getResetDebugSequence.cjs.js');

function mergeDebugSequence(atomicClases, resetClassName) {
  const debugResultRootAtomic = atomicClases ? getAtomicDebugSequenceTree.getAtomicDebugSequenceTree(atomicClases) : undefined;
  const debugResultRootReset = resetClassName ? getResetDebugSequence.getResetDebugSequence(resetClassName) : undefined;
  if (!debugResultRootAtomic && !debugResultRootReset) {
    return undefined;
  }
  if (!debugResultRootAtomic) {
    return debugResultRootReset;
  }
  if (!debugResultRootReset) {
    return debugResultRootAtomic;
  }
  const debugResultRoot = {
    sequenceHash: debugResultRootAtomic.sequenceHash + debugResultRootReset.sequenceHash,
    direction: debugResultRootAtomic.direction,
    children: [debugResultRootAtomic, debugResultRootReset],
    debugClassNames: [...debugResultRootAtomic.debugClassNames, ...debugResultRootReset.debugClassNames]
  };
  return debugResultRoot;
}

exports.mergeDebugSequence = mergeDebugSequence;
//# sourceMappingURL=mergeDebugSequence.cjs.js.map
