"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "renderSwatchPickerGrid", {
    enumerable: true,
    get: function() {
        return renderSwatchPickerGrid;
    }
});
const _interop_require_wildcard = require("@swc/helpers/_/_interop_require_wildcard");
const _react = /*#__PURE__*/ _interop_require_wildcard._(require("react"));
const _ = require("../");
const renderSwatchPickerGrid = (props)=>{
    const { items, columnCount, renderRow, renderSwatch } = props;
    const _renderRow = renderRow || (({ children, rowId })=>/*#__PURE__*/ _react.createElement(_.SwatchPickerRow, {
            key: rowId
        }, children));
    const _renderSwatch = renderSwatch || ((item)=>{
        var _item_src;
        return item.src ? /*#__PURE__*/ _react.createElement(_.ImageSwatch, {
            key: item.value,
            src: (_item_src = item.src) !== null && _item_src !== void 0 ? _item_src : '',
            ...item
        }) : /*#__PURE__*/ _react.createElement(_.ColorSwatch, {
            key: item.value,
            color: item.color || '',
            ...item
        });
    });
    const rowCount = Math.ceil(items.length / columnCount);
    const rows = Array.from({
        length: rowCount
    }, (_, i)=>{
        const start = i * columnCount;
        const end = start + columnCount;
        return items.slice(start, end);
    });
    return rows.map((row, index)=>_renderRow({
            children: row.map(_renderSwatch),
            rowId: index
        }));
};
