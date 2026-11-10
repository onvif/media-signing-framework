import * as ReactDOM from 'react-dom';
import * as React from 'react';
/**
 * Render the final JSX of Portal
 */ export const renderPortal_unstable = (state)=>{
    return /*#__PURE__*/ React.createElement("span", {
        hidden: true,
        ref: state.virtualParentRootRef
    }, state.mountNode && /*#__PURE__*/ ReactDOM.createPortal(/*#__PURE__*/ React.createElement(React.Fragment, null, state.children, /*#__PURE__*/ React.createElement("span", {
        hidden: true
    })), state.mountNode));
};
