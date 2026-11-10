"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderTeachingPopoverCarouselNav_unstable", {
    enumerable: true,
    get: function() {
        return renderTeachingPopoverCarouselNav_unstable;
    }
});
const _jsxruntime = require("@fluentui/react-jsx-runtime/jsx-runtime");
const _reactutilities = require("@fluentui/react-utilities");
const _valueIdContext = require("./valueIdContext");
const renderTeachingPopoverCarouselNav_unstable = (state)=>{
    (0, _reactutilities.assertSlots)(state);
    const { values, renderNavButton } = state;
    return /*#__PURE__*/ (0, _jsxruntime.jsx)(state.root, {
        children: values.map((value)=>/*#__PURE__*/ (0, _jsxruntime.jsx)(_valueIdContext.ValueIdContextProvider, {
                value: value,
                children: renderNavButton(value)
            }, value))
    });
};
