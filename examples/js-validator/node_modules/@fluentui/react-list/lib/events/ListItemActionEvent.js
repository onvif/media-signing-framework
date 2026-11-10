import * as React from 'react';
export const ListItemActionEventName = 'ListItemAction';
export const createListItemActionEvent = (originalEvent)=>new CustomEvent(ListItemActionEventName, {
        cancelable: true,
        bubbles: true,
        detail: {
            originalEvent
        }
    });
