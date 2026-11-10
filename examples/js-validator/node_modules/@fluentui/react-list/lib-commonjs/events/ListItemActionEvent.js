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
    ListItemActionEventName: function() {
        return ListItemActionEventName;
    },
    createListItemActionEvent: function() {
        return createListItemActionEvent;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const ListItemActionEventName = 'ListItemAction';
const createListItemActionEvent = (originalEvent)=>new CustomEvent(ListItemActionEventName, {
        cancelable: true,
        bubbles: true,
        detail: {
            originalEvent
        }
    });
