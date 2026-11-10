import * as React from 'react';
/**
 * Given `children`, return an object mapping key to child.
 */ export function getChildMapping(children) {
    const childMapping = {};
    if (children) {
        React.Children.toArray(children).forEach((child)=>{
            if (React.isValidElement(child)) {
                var _child_key;
                childMapping[(_child_key = child.key) !== null && _child_key !== void 0 ? _child_key : ''] = {
                    appear: false,
                    element: child,
                    visible: true,
                    unmountOnExit: true
                };
            }
        });
    }
    return childMapping;
}
