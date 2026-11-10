  import { jsx as _jsx, jsxs as _jsxs } from "@fluentui/react-jsx-runtime/jsx-runtime";
import * as React from 'react';
import { assertSlots } from '@fluentui/react-utilities';
/**
 * @deprecated migrated to \@fluentui\-contrib/react\-virtualizer for stable release.
 */ export const renderVirtualizer_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsxs(React.Fragment, {
        children: [
            /*#__PURE__*/ _jsx(state.beforeContainer, {
                children: /*#__PURE__*/ _jsx(state.before, {})
            }),
            state.virtualizedChildren,
            /*#__PURE__*/ _jsx(state.afterContainer, {
                children: /*#__PURE__*/ _jsx(state.after, {})
            })
        ]
    });
};
/**
 * @deprecated migrated to \@fluentui\-contrib/react\-virtualizer for stable release.
 */ export const renderVirtualizerChildPlaceholder = (child, index)=>{
    return /*#__PURE__*/ _jsx(React.Suspense, {
        fallback: null,
        children: child
    }, `fui-virtualizer-placeholder-${index}`);
};
