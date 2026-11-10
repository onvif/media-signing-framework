import * as React from 'react';
import { getIntrinsicElementProps, slot } from '@fluentui/react-utilities';
/**
 * Returns the props and state required to render the component
 * @param props - TeachingPopoverBody properties
 * @param ref - reference to root HTMLElement of TeachingPopoverBody
 */ export const useTeachingPopoverBody_unstable = (props, ref)=>{
    const { mediaLength } = props;
    return {
        components: {
            root: 'div',
            media: 'span'
        },
        root: slot.always(getIntrinsicElementProps('div', {
            ref,
            ...props
        }), {
            elementType: 'div'
        }),
        media: slot.optional(props.media, {
            elementType: 'span'
        }),
        mediaLength: mediaLength !== null && mediaLength !== void 0 ? mediaLength : 'short'
    };
};
