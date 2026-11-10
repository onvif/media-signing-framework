import * as React from 'react';
import { AnnounceProvider } from '@fluentui/react-shared-contexts';
export const renderAriaLiveAnnouncer_unstable = (state, contextValues)=>{
    return /*#__PURE__*/ React.createElement(AnnounceProvider, {
        value: contextValues.announce
    }, state.children);
};
