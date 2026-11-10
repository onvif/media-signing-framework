"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "useTeachingPopoverBody_unstable", {
    enumerable: true,
    get: function() {
        return useTeachingPopoverBody_unstable;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _reactutilities = require("@fluentui/react-utilities");
const useTeachingPopoverBody_unstable = (props, ref)=>{
    const { mediaLength } = props;
    return {
        components: {
            root: 'div',
            media: 'span'
        },
        root: _reactutilities.slot.always((0, _reactutilities.getIntrinsicElementProps)('div', {
            ref,
            ...props
        }), {
            elementType: 'div'
        }),
        media: _reactutilities.slot.optional(props.media, {
            elementType: 'span'
        }),
        mediaLength: mediaLength !== null && mediaLength !== void 0 ? mediaLength : 'short'
    };
};
