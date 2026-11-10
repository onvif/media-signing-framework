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
    SSRContext: function() {
        return _SSRContext.SSRContext;
    },
    SSRProvider: function() {
        return _SSRContext.SSRProvider;
    },
    canUseDOM: function() {
        return _canUseDOM.canUseDOM;
    },
    defaultSSRContextValue: function() {
        return _SSRContext.defaultSSRContextValue;
    },
    useIsSSR: function() {
        return _SSRContext.useIsSSR;
    },
    useSSRContext: function() {
        return _SSRContext.useSSRContext;
    }
});
const _canUseDOM = require("./canUseDOM");
const _SSRContext = require("./SSRContext");
