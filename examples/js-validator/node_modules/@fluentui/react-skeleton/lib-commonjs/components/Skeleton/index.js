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
    renderSkeleton_unstable: function() {
        return _renderSkeleton.renderSkeleton_unstable;
    },
    skeletonClassNames: function() {
        return _useSkeletonStylesstyles.skeletonClassNames;
    },
    useSkeletonContextValues: function() {
        return _useSkeletonContextValues.useSkeletonContextValues;
    },
    useSkeletonStyles_unstable: function() {
        return _useSkeletonStylesstyles.useSkeletonStyles_unstable;
    },
    useSkeleton_unstable: function() {
        return _useSkeleton.useSkeleton_unstable;
    }
});
const _Skeleton = require("./Skeleton");
const _renderSkeleton = require("./renderSkeleton");
const _useSkeleton = require("./useSkeleton");
const _useSkeletonContextValues = require("./useSkeletonContextValues");
const _useSkeletonStylesstyles = require("./useSkeletonStyles.styles");
