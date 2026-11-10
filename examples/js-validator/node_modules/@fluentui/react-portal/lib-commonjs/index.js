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
    Portal: function() {
        return _index.Portal;
    },
    elementContains: function() {
        return _reactutilities.elementContains;
    },
    renderPortal_unstable: function() {
        return _index.renderPortal_unstable;
    },
    setVirtualParent: function() {
        return _reactutilities.setVirtualParent;
    },
    toMountNodeProps: function() {
        return _toMountNodeProps.toMountNodeProps;
    },
    usePortal_unstable: function() {
        return _index.usePortal_unstable;
    }
});
const _reactutilities = require("@fluentui/react-utilities");
const _index = require("./components/Portal/index");
const _toMountNodeProps = require("./utils/toMountNodeProps");
