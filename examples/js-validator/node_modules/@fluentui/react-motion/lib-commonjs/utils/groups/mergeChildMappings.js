"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "mergeChildMappings", {
    enumerable: true,
    get: function() {
        return mergeChildMappings;
    }
});
function mergeChildMappings(prevMapping, nextMapping) {
    function getValueForKey(key) {
        return key in nextMapping ? nextMapping[key] : prevMapping[key];
    }
    // For each key of `next`, the list of keys to insert before that key in
    // the combined list
    const nextKeysPending = {};
    let pendingKeys = [];
    // eslint-disable-next-line guard-for-in
    for(const prevKey in prevMapping){
        if (prevKey in nextMapping) {
            if (pendingKeys.length) {
                nextKeysPending[prevKey] = pendingKeys;
                pendingKeys = [];
            }
            continue;
        }
        pendingKeys.push(prevKey);
    }
    const childMapping = {};
    // eslint-disable-next-line guard-for-in
    for(const nextKey in nextMapping){
        if (nextKeysPending[nextKey]) {
            for (const pendingNextKey of nextKeysPending[nextKey]){
                childMapping[pendingNextKey] = getValueForKey(pendingNextKey);
            }
        }
        childMapping[nextKey] = getValueForKey(nextKey);
    }
    // Finally, add the keys which didn't appear before any key in `next`
    for (const pendingKey of pendingKeys){
        childMapping[pendingKey] = getValueForKey(pendingKey);
    }
    return childMapping;
}
