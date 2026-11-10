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
    AnnounceProvider: function() {
        return _AnnounceContext.AnnounceProvider;
    },
    useAnnounce: function() {
        return _AnnounceContext.useAnnounce;
    }
});
const _AnnounceContext = require("./AnnounceContext");
