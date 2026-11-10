export const scrollIntoView = (target)=>{
    if (!target) {
        return;
    }
    const scrollParent = findScrollableParent(target.parentElement);
    if (!scrollParent) {
        return;
    }
    const { offsetHeight } = target;
    const offsetTop = getTotalOffsetTop(target, scrollParent);
    const { scrollMarginTop, scrollMarginBottom } = getScrollMargins(target);
    const { offsetHeight: parentOffsetHeight, scrollTop } = scrollParent;
    const isAbove = offsetTop - scrollMarginTop < scrollTop;
    const isBelow = offsetTop + offsetHeight + scrollMarginBottom > scrollTop + parentOffsetHeight;
    const buffer = 2;
    if (isAbove) {
        scrollParent.scrollTo(0, offsetTop - scrollMarginTop - buffer);
    } else if (isBelow) {
        scrollParent.scrollTo(0, offsetTop + offsetHeight + scrollMarginBottom - parentOffsetHeight + buffer);
    }
};
const findScrollableParent = (element)=>{
    if (!element) {
        return null;
    }
    if (element.scrollHeight > element.offsetHeight) {
        return element;
    }
    return findScrollableParent(element.parentElement);
};
const getTotalOffsetTop = (element, scrollParent)=>{
    if (!element || element === scrollParent) {
        return 0;
    }
    if (element.contains(scrollParent)) {
        // subtract the scroll parent's offset top from the running total if the offsetParent is above it
        return scrollParent.offsetTop * -1;
    }
    return element.offsetTop + getTotalOffsetTop(element.offsetParent, scrollParent);
};
const getScrollMargins = (element)=>{
    var _element_ownerDocument;
    const win = (_element_ownerDocument = element.ownerDocument) === null || _element_ownerDocument === void 0 ? void 0 : _element_ownerDocument.defaultView;
    if (!win) {
        return {
            scrollMarginTop: 0,
            scrollMarginBottom: 0
        };
    }
    const computedStyles = win.getComputedStyle(element);
    var _getIntValueOfComputedStyle;
    const scrollMarginTop = (_getIntValueOfComputedStyle = getIntValueOfComputedStyle(computedStyles.scrollMarginTop)) !== null && _getIntValueOfComputedStyle !== void 0 ? _getIntValueOfComputedStyle : getIntValueOfComputedStyle(computedStyles.scrollMarginBlockStart);
    var _getIntValueOfComputedStyle1;
    const scrollMarginBottom = (_getIntValueOfComputedStyle1 = getIntValueOfComputedStyle(computedStyles.scrollMarginBottom)) !== null && _getIntValueOfComputedStyle1 !== void 0 ? _getIntValueOfComputedStyle1 : getIntValueOfComputedStyle(computedStyles.scrollMarginBlockEnd);
    return {
        scrollMarginTop,
        scrollMarginBottom
    };
};
const getIntValueOfComputedStyle = (computedStyle)=>{
    return computedStyle ? parseInt(computedStyle, 10) : 0;
};
