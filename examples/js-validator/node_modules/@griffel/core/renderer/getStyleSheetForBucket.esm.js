import { DATA_BUCKET_ATTR, DATA_PRIORITY_ATTR } from '../constants.esm.js';
import { createIsomorphicStyleSheet } from './createIsomorphicStyleSheet.esm.js';

/**
 * Ordered style buckets using their short pseudo name.
 *
 * @internal
 */
const styleBucketOrdering = [
// reset styles
'r',
// catch-all
'd',
// link
'l',
// visited
'v',
// focus-within
'w',
// focus
'f',
// focus-visible
'i',
// hover
'h',
// active
'a',
// at rules for reset styles
's',
// keyframes
'k',
// at-rules
't',
// @media rules
'm',
// @container rules
'c'];
// avoid repeatedly calling `indexOf` to determine order during new insertions
const styleBucketOrderingMap = /*#__PURE__*/styleBucketOrdering.reduce((acc, cur, j) => {
  acc[cur] = j;
  return acc;
}, {});
function getStyleSheetKey(bucketName, media, priority) {
  return (bucketName === 'm' ? bucketName + media : bucketName) + priority;
}
function getStyleSheetKeyFromElement(styleEl) {
  var _a;
  const bucketName = styleEl.getAttribute(DATA_BUCKET_ATTR);
  const priority = (_a = styleEl.getAttribute(DATA_PRIORITY_ATTR)) !== null && _a !== void 0 ? _a : '0';
  return getStyleSheetKey(bucketName, styleEl.media, priority);
}
/**
 * Lazily adds a `<style>` bucket to the `<head>`. This will ensure that the style buckets are ordered.
 */
function getStyleSheetForBucket(bucketName, targetDocument, insertionPoint, renderer, metadata = {}) {
  var _a, _b;
  const isMediaBucket = bucketName === 'm';
  const media = (_a = metadata['m']) !== null && _a !== void 0 ? _a : '0';
  const priority = (_b = metadata['p']) !== null && _b !== void 0 ? _b : 0;
  const stylesheetKey = getStyleSheetKey(bucketName, media, priority);
  if (!renderer.stylesheets[stylesheetKey]) {
    const tag = targetDocument && targetDocument.createElement('style');
    const stylesheet = createIsomorphicStyleSheet(tag, bucketName, priority, Object.assign({}, renderer.styleElementAttributes, isMediaBucket && {
      media
    }));
    renderer.stylesheets[stylesheetKey] = stylesheet;
    if ((targetDocument === null || targetDocument === void 0 ? void 0 : targetDocument.head) && tag) {
      targetDocument.head.insertBefore(tag, findInsertionPoint(targetDocument, insertionPoint, bucketName, renderer, metadata));
    }
  }
  return renderer.stylesheets[stylesheetKey];
}
function isSameInsertionKey(element, bucketName, metadata) {
  var _a, _b;
  const targetKey = bucketName + ((_a = metadata['m']) !== null && _a !== void 0 ? _a : '');
  const elementKey = element.getAttribute(DATA_BUCKET_ATTR) + ((_b = element.media) !== null && _b !== void 0 ? _b : '');
  return targetKey === elementKey;
}
/**
 * Finds an element before which the new bucket style element should be inserted following the bucket sort order.
 *
 * @param targetDocument - A document
 * @param insertionPoint - An element that will be used as an initial insertion point
 * @param targetBucket - The bucket that should be inserted to DOM
 * @param renderer - Griffel renderer
 * @param metadata - metadata for CSS rule
 * @returns - Smallest style element with greater sort order than the current bucket
 */
function findInsertionPoint(targetDocument, insertionPoint, targetBucket, renderer, metadata = {}) {
  var _a, _b;
  const targetOrder = styleBucketOrderingMap[targetBucket];
  const media = (_a = metadata['m']) !== null && _a !== void 0 ? _a : '';
  const priority = (_b = metadata['p']) !== null && _b !== void 0 ? _b : 0;
  // Similar to javascript sort comparators where
  // a positive value is increasing sort order
  // a negative value is decreasing sort order
  let comparer = el => targetOrder - styleBucketOrderingMap[el.getAttribute(DATA_BUCKET_ATTR)];
  let styleElements = targetDocument.head.querySelectorAll(`[${DATA_BUCKET_ATTR}]`);
  if (targetBucket === 'm') {
    const mediaElements = targetDocument.head.querySelectorAll(`[${DATA_BUCKET_ATTR}="${targetBucket}"]`);
    // only reduce the scope of the search and change comparer
    // if there are other media buckets already on the page
    if (mediaElements.length) {
      styleElements = mediaElements;
      comparer = el => renderer.compareMediaQueries(media, el.media);
    }
  }
  const comparerWithPriority = el => {
    if (isSameInsertionKey(el, targetBucket, metadata)) {
      return priority - Number(el.getAttribute('data-priority'));
    }
    return comparer(el);
  };
  const length = styleElements.length;
  let index = length - 1;
  while (index >= 0) {
    const styleElement = styleElements.item(index);
    if (comparerWithPriority(styleElement) > 0) {
      return styleElement.nextSibling;
    }
    index--;
  }
  if (length > 0) {
    return styleElements.item(0);
  }
  return insertionPoint ? insertionPoint.nextSibling : null;
}

export { getStyleSheetForBucket, getStyleSheetKey, getStyleSheetKeyFromElement, styleBucketOrdering };
//# sourceMappingURL=getStyleSheetForBucket.esm.js.map
