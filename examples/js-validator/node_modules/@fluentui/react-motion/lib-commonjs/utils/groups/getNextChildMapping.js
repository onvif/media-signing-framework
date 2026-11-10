"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "getNextChildMapping", {
    enumerable: true,
    get: function() {
        return getNextChildMapping;
    }
});
const _mergeChildMappings = require("./mergeChildMappings");
function getNextChildMapping(prevChildMapping, nextChildMapping) {
    const childrenMapping = (0, _mergeChildMappings.mergeChildMappings)(prevChildMapping, nextChildMapping);
    Object.entries(childrenMapping).forEach(([key, childDefinition])=>{
        const hasPrev = key in prevChildMapping;
        const hasNext = key in nextChildMapping;
        if (hasNext) {
            // Case 1: item hasn't changed transition states
            if (hasPrev) {
                childrenMapping[key] = {
                    ...childDefinition
                };
                return;
            }
            // Case 2: item is new (entering)
            childrenMapping[key] = {
                ...childDefinition,
                appear: true,
                visible: true
            };
            return;
        }
        // Case 3: item is leaving
        childrenMapping[key] = {
            ...childDefinition,
            visible: false
        };
    });
    return childrenMapping;
}
