/*!
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */ /**
 * WARNING! ATTENTION! WARNING! ATTENTION! WARNING! ATTENTION!
 * WARNING! ATTENTION! WARNING! ATTENTION! WARNING! ATTENTION!
 *
 * Do not use anything from this file. It is a snapshot of the older Tabster typings exposed by a mistake.
 * The exposed typings should have been removed, but we don't do it in minor versions to avoid breaking changes.
 * Everything reexported from this file as react-tabster/TabsterTypes is marked as deprecated and shouldn't
 * be used anywhre.
 *
 * WARNING! ATTENTION! WARNING! ATTENTION! WARNING! ATTENTION!
 * WARNING! ATTENTION! WARNING! ATTENTION! WARNING! ATTENTION!
 */ "use strict";
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
    DeloserEventName: function() {
        return DeloserEventName;
    },
    FocusInEventName: function() {
        return FocusInEventName;
    },
    FocusOutEventName: function() {
        return FocusOutEventName;
    },
    FocusableSelector: function() {
        return FocusableSelector;
    },
    GroupperMoveFocusActions: function() {
        return GroupperMoveFocusActions;
    },
    GroupperMoveFocusEventName: function() {
        return GroupperMoveFocusEventName;
    },
    GroupperTabbabilities: function() {
        return GroupperTabbabilities;
    },
    ModalizerActiveEventName: function() {
        return ModalizerActiveEventName;
    },
    ModalizerBeforeFocusOutEventName: function() {
        return ModalizerBeforeFocusOutEventName;
    },
    ModalizerFocusInEventName: function() {
        return ModalizerFocusInEventName;
    },
    ModalizerFocusOutEventName: function() {
        return ModalizerFocusOutEventName;
    },
    ModalizerInactiveEventName: function() {
        return ModalizerInactiveEventName;
    },
    MoveFocusEventName: function() {
        return MoveFocusEventName;
    },
    MoverDirections: function() {
        return MoverDirections;
    },
    MoverEventName: function() {
        return MoverEventName;
    },
    MoverKeys: function() {
        return MoverKeys;
    },
    MoverMoveFocusEventName: function() {
        return MoverMoveFocusEventName;
    },
    ObservedElementAccesibilities: function() {
        return ObservedElementAccesibilities;
    },
    RestoreFocusOrders: function() {
        return RestoreFocusOrders;
    },
    RestorerTypes: function() {
        return RestorerTypes;
    },
    SysDummyInputsPositions: function() {
        return SysDummyInputsPositions;
    },
    TabsterAttributeName: function() {
        return TabsterAttributeName;
    },
    TabsterDummyInputAttributeName: function() {
        return TabsterDummyInputAttributeName;
    },
    Visibilities: function() {
        return Visibilities;
    }
});
const TabsterAttributeName = 'data-tabster';
const TabsterDummyInputAttributeName = 'data-tabster-dummy';
const DeloserEventName = 'tabster:deloser';
const ModalizerActiveEventName = 'tabster:modalizer:active';
const ModalizerInactiveEventName = 'tabster:modalizer:inactive';
const ModalizerFocusInEventName = 'tabster:modalizer:focusin';
const ModalizerFocusOutEventName = 'tabster:modalizer:focusout';
const ModalizerBeforeFocusOutEventName = 'tabster:modalizer:beforefocusout';
const MoverEventName = 'tabster:mover';
const FocusInEventName = 'tabster:focusin';
const FocusOutEventName = 'tabster:focusout';
const MoveFocusEventName = 'tabster:movefocus';
const MoverMoveFocusEventName = 'tabster:mover:movefocus';
const GroupperMoveFocusEventName = 'tabster:groupper:movefocus';
const FocusableSelector = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '*[tabindex]',
    '*[contenteditable]'
].join(', ');
const GroupperMoveFocusActions = {
    Enter: 1,
    Escape: 2
};
const ObservedElementAccesibilities = {
    Any: 0,
    Accessible: 1,
    Focusable: 2
};
const RestoreFocusOrders = {
    History: 0,
    DeloserDefault: 1,
    RootDefault: 2,
    DeloserFirst: 3,
    RootFirst: 4
};
const Visibilities = {
    Invisible: 0,
    PartiallyVisible: 1,
    Visible: 2
};
const RestorerTypes = {
    Source: 0,
    Target: 1
};
const MoverDirections = {
    Both: 0,
    Vertical: 1,
    Horizontal: 2,
    Grid: 3,
    GridLinear: 4
};
const MoverKeys = {
    ArrowUp: 1,
    ArrowDown: 2,
    ArrowLeft: 3,
    ArrowRight: 4,
    PageUp: 5,
    PageDown: 6,
    Home: 7,
    End: 8
};
const GroupperTabbabilities = {
    Unlimited: 0,
    Limited: 1,
    LimitedTrapFocus: 2
};
const SysDummyInputsPositions = {
    Auto: 0,
    Inside: 1,
    Outside: 2
};
