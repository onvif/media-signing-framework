import * as React from 'react';
import { getNativeElementProps } from '../utils/getNativeElementProps';
/**
 * Given an element tagname and user props, filters the props to only allowed props for the given
 * element type.
 *
 * Equivalent to {@link getNativeElementProps}, but more type-safe.
 *
 * @param tagName - The slot's default element type (e.g. 'div')
 * @param props - The component's props object
 * @param excludedPropNames - List of native props to exclude from the returned value
 */ export const getIntrinsicElementProps = (tagName, // eslint-disable-next-line @typescript-eslint/no-restricted-types -- in order to not introduce Type Restriction CHANGe which is kinda "breaking change from Types POV", we don't enforce our custom `RefAttributes` in this API, to be compatible with scenarios where non v9 interfaces might be used. This may/will change with React 19
props, excludedPropNames)=>{
    var _props_as;
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return getNativeElementProps((_props_as = props.as) !== null && _props_as !== void 0 ? _props_as : tagName, props, excludedPropNames);
};
