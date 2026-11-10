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
    GroupperMoveFocusActions: function() {
        return _tabster.GroupperMoveFocusActions;
    },
    GroupperMoveFocusEvent: function() {
        return _tabster.GroupperMoveFocusEvent;
    },
    GroupperMoveFocusEventName: function() {
        return _tabster.GroupperMoveFocusEventName;
    },
    KEYBORG_FOCUSIN: function() {
        return _keyborg.KEYBORG_FOCUSIN;
    },
    MoverKeys: function() {
        return _tabster.MoverKeys;
    },
    MoverMemorizedElementEvent: function() {
        return _tabster.MoverMemorizedElementEvent;
    },
    MoverMemorizedElementEventName: function() {
        return _tabster.MoverMemorizedElementEventName;
    },
    MoverMoveFocusEvent: function() {
        return _tabster.MoverMoveFocusEvent;
    },
    MoverMoveFocusEventName: function() {
        return _tabster.MoverMoveFocusEventName;
    },
    TabsterMoveFocusEvent: function() {
        return _tabster.TabsterMoveFocusEvent;
    },
    TabsterMoveFocusEventName: function() {
        return _tabster.TabsterMoveFocusEventName;
    },
    TabsterTypes: function() {
        return /** @deprecated (Do not use! Exposed by mistake and will be removed in the next major version.)  */ _tabstertypes601donotuse;
    },
    applyFocusVisiblePolyfill: function() {
        return _index1.applyFocusVisiblePolyfill;
    },
    createCustomFocusIndicatorStyle: function() {
        return _index1.createCustomFocusIndicatorStyle;
    },
    createFocusOutlineStyle: function() {
        return _index1.createFocusOutlineStyle;
    },
    /** @deprecated Use element.dispatchEvent(new GroupperMoveFocusEvent({ action: GroupperMoveFocusActions.Escape })) */ dispatchGroupperMoveFocusEvent: function() {
        return _tabster.dispatchGroupperMoveFocusEvent;
    },
    /** @deprecated Use element.dispatchEvent(new MoverMoveFocusEvent({ key: MoverKeys.ArrowDown })) */ dispatchMoverMoveFocusEvent: function() {
        return _tabster.dispatchMoverMoveFocusEvent;
    },
    useActivateModal: function() {
        return _index.useActivateModal;
    },
    useArrowNavigationGroup: function() {
        return _index.useArrowNavigationGroup;
    },
    useDangerousNeverHidden_unstable: function() {
        return _index.useDangerousNeverHidden_unstable;
    },
    useFocusFinders: function() {
        return _index.useFocusFinders;
    },
    useFocusObserved: function() {
        return _index.useFocusObserved;
    },
    useFocusVisible: function() {
        return _index.useFocusVisible;
    },
    useFocusWithin: function() {
        return _index.useFocusWithin;
    },
    useFocusableGroup: function() {
        return _index.useFocusableGroup;
    },
    useFocusedElementChange: function() {
        return _index.useFocusedElementChange;
    },
    useIsNavigatingWithKeyboard: function() {
        return _index.useIsNavigatingWithKeyboard;
    },
    useKeyboardNavAttribute: function() {
        return _index.useKeyboardNavAttribute;
    },
    useMergedTabsterAttributes_unstable: function() {
        return _index.useMergedTabsterAttributes_unstable;
    },
    useModalAttributes: function() {
        return _index.useModalAttributes;
    },
    useObservedElement: function() {
        return _index.useObservedElement;
    },
    useOnKeyboardNavigationChange: function() {
        return _index.useOnKeyboardNavigationChange;
    },
    useRestoreFocusSource: function() {
        return _index.useRestoreFocusSource;
    },
    useRestoreFocusTarget: function() {
        return _index.useRestoreFocusTarget;
    },
    useSetKeyboardNavigation: function() {
        return _index.useSetKeyboardNavigation;
    },
    useTabsterAttributes: function() {
        return _index.useTabsterAttributes;
    },
    useUncontrolledFocus: function() {
        return _index.useUncontrolledFocus;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _index = require("./hooks/index");
const _index1 = require("./focus/index");
const _tabster = require("tabster");
const _keyborg = require("keyborg");
const _tabstertypes601donotuse = /*#__PURE__*/ _interop_require_wildcard._(require("./tabster-types-6.0.1-do-not-use"));
