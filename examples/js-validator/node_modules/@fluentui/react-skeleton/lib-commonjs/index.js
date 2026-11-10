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
    Skeleton: function() {
        return _Skeleton.Skeleton;
    },
    SkeletonContextProvider: function() {
        return _index.SkeletonContextProvider;
    },
    SkeletonItem: function() {
        return _SkeletonItem.SkeletonItem;
    },
    renderSkeletonItem_unstable: function() {
        return _SkeletonItem.renderSkeletonItem_unstable;
    },
    renderSkeleton_unstable: function() {
        return _Skeleton.renderSkeleton_unstable;
    },
    skeletonClassNames: function() {
        return _Skeleton.skeletonClassNames;
    },
    skeletonItemClassNames: function() {
        return _SkeletonItem.skeletonItemClassNames;
    },
    useSkeletonContext: function() {
        return _index.useSkeletonContext;
    },
    useSkeletonItemStyles_unstable: function() {
        return _SkeletonItem.useSkeletonItemStyles_unstable;
    },
    useSkeletonItem_unstable: function() {
        return _SkeletonItem.useSkeletonItem_unstable;
    },
    useSkeletonStyles_unstable: function() {
        return _Skeleton.useSkeletonStyles_unstable;
    },
    useSkeleton_unstable: function() {
        return _Skeleton.useSkeleton_unstable;
    }
});
const _Skeleton = require("./Skeleton");
const _SkeletonItem = require("./SkeletonItem");
const _index = require("./contexts/index");
