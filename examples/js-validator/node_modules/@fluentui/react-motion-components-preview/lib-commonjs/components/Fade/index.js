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
    Fade: function() {
        return _Fade.Fade;
    },
    FadeRelaxed: function() {
        return _Fade.FadeRelaxed;
    },
    FadeSnappy: function() {
        return _Fade.FadeSnappy;
    }
});
const _Fade = require("./Fade");
