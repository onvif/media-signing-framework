"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    SkeletonContextProvider: function() {
        return _SkeletonContext.SkeletonContextProvider;
    },
    useSkeletonContext: function() {
        return _SkeletonContext.useSkeletonContext;
    }
});
const _SkeletonContext = require("./SkeletonContext");
