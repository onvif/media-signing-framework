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
 */ export const TabsterAttributeName = 'data-tabster';
export const TabsterDummyInputAttributeName = 'data-tabster-dummy';
export const DeloserEventName = 'tabster:deloser';
export const ModalizerActiveEventName = 'tabster:modalizer:active';
export const ModalizerInactiveEventName = 'tabster:modalizer:inactive';
export const ModalizerFocusInEventName = 'tabster:modalizer:focusin';
export const ModalizerFocusOutEventName = 'tabster:modalizer:focusout';
export const ModalizerBeforeFocusOutEventName = 'tabster:modalizer:beforefocusout';
export const MoverEventName = 'tabster:mover';
export const FocusInEventName = 'tabster:focusin';
export const FocusOutEventName = 'tabster:focusout';
// Event to be triggered when Tabster wants to move focus as the result of
// keyboard event. This allows to preventDefault() if you want to have
// some custom logic.
export const MoveFocusEventName = 'tabster:movefocus';
// Event that can be triggered by the application to programmatically move
// focus inside Mover.
export const MoverMoveFocusEventName = 'tabster:mover:movefocus';
// Event that can be triggered by the application to programmatically enter
// or escape Groupper.
export const GroupperMoveFocusEventName = 'tabster:groupper:movefocus';
export const FocusableSelector = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '*[tabindex]',
    '*[contenteditable]'
].join(', ');
export const GroupperMoveFocusActions = {
    Enter: 1,
    Escape: 2
};
export const ObservedElementAccesibilities = {
    Any: 0,
    Accessible: 1,
    Focusable: 2
};
export const RestoreFocusOrders = {
    History: 0,
    DeloserDefault: 1,
    RootDefault: 2,
    DeloserFirst: 3,
    RootFirst: 4
};
export const Visibilities = {
    Invisible: 0,
    PartiallyVisible: 1,
    Visible: 2
};
export const RestorerTypes = {
    Source: 0,
    Target: 1
};
export const MoverDirections = {
    Both: 0,
    Vertical: 1,
    Horizontal: 2,
    Grid: 3,
    GridLinear: 4
};
export const MoverKeys = {
    ArrowUp: 1,
    ArrowDown: 2,
    ArrowLeft: 3,
    ArrowRight: 4,
    PageUp: 5,
    PageDown: 6,
    Home: 7,
    End: 8
};
export const GroupperTabbabilities = {
    Unlimited: 0,
    Limited: 1,
    LimitedTrapFocus: 2
};
export const SysDummyInputsPositions = {
    Auto: 0,
    Inside: 1,
    Outside: 2
};
