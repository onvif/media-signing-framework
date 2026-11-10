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
    LinkContextProvider: function() {
        return _linkContext.LinkContextProvider;
    },
    linkContextDefaultValue: function() {
        return _linkContext.linkContextDefaultValue;
    },
    useLinkContext: function() {
        return _linkContext.useLinkContext;
    }
});
const _linkContext = require("./linkContext");
