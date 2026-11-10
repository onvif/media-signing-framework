'use strict';

var hashString = require('@emotion/hash');
var core = require('rtl-css-js/core');
var constants = require('../constants.cjs.js');
var compileAtomicCSSRule = require('./compileAtomicCSSRule.cjs.js');
var compileKeyframeCSS = require('./compileKeyframeCSS.cjs.js');
var shorthands = require('./shorthands.cjs.js');
var generateCombinedMediaQuery = require('./utils/generateCombinedMediaQuery.cjs.js');
var isMediaQuerySelector = require('./utils/isMediaQuerySelector.cjs.js');
var isLayerSelector = require('./utils/isLayerSelector.cjs.js');
var isNestedSelector = require('./utils/isNestedSelector.cjs.js');
var isSupportQuerySelector = require('./utils/isSupportQuerySelector.cjs.js');
var isContainerQuerySelector = require('./utils/isContainerQuerySelector.cjs.js');
var normalizeNestedProperty = require('./utils/normalizeNestedProperty.cjs.js');
var isObject = require('./utils/isObject.cjs.js');
var getStyleBucketName = require('./getStyleBucketName.cjs.js');
var hashClassName = require('./utils/hashClassName.cjs.js');
var hashPropertyKey = require('./utils/hashPropertyKey.cjs.js');
var isResetValue = require('./utils/isResetValue.cjs.js');
var trimSelector = require('./utils/trimSelector.cjs.js');
var warnAboutUnresolvedRule = require('./warnings/warnAboutUnresolvedRule.cjs.js');
var warnAboutUnsupportedProperties = require('./warnings/warnAboutUnsupportedProperties.cjs.js');

function _interopDefaultCompat (e) { return e && typeof e === 'object' && 'default' in e ? e : { default: e }; }

var hashString__default = /*#__PURE__*/_interopDefaultCompat(hashString);

function getShorthandDefinition(property) {
  return shorthands.shorthands[property];
}
function computePropertyPriority(shorthand) {
  var _a;
  return (_a = shorthand === null || shorthand === void 0 ? void 0 : shorthand[0]) !== null && _a !== void 0 ? _a : 0;
}
function pushToClassesMap(classesMap, propertyKey, ltrClassname, rtlClassname) {
  classesMap[propertyKey] = rtlClassname ? [ltrClassname, rtlClassname] : ltrClassname;
}
function createBucketEntry(cssRule, metadata) {
  if (metadata.length > 0) {
    return [cssRule, Object.fromEntries(metadata)];
  }
  return cssRule;
}
function pushToCSSRules(cssRulesByBucket, styleBucketName, ltrCSS, rtlCSS, media, priority) {
  var _a;
  const metadata = [];
  if (priority !== 0) {
    metadata.push(['p', priority]);
  }
  if (styleBucketName === 'm' && media) {
    metadata.push(['m', media]);
  }
  (_a = cssRulesByBucket[styleBucketName]) !== null && _a !== void 0 ? _a : cssRulesByBucket[styleBucketName] = [];
  if (ltrCSS) {
    cssRulesByBucket[styleBucketName].push(createBucketEntry(ltrCSS, metadata));
  }
  if (rtlCSS) {
    cssRulesByBucket[styleBucketName].push(createBucketEntry(rtlCSS, metadata));
  }
}
/**
 * Transforms input styles to classes maps & CSS rules.
 *
 * @internal
 */
function resolveStyleRules(styles, classNameHashSalt = '', selectors = [], atRules = {
  container: '',
  layer: '',
  media: '',
  supports: ''
}, cssClassesMap = {}, cssRulesByBucket = {}, rtlValue) {
  // eslint-disable-next-line guard-for-in
  for (const property in styles) {
    // eslint-disable-next-line no-prototype-builtins
    if (constants.UNSUPPORTED_CSS_PROPERTIES.hasOwnProperty(property)) {
      warnAboutUnsupportedProperties.warnAboutUnsupportedProperties(property, styles[property]);
      continue;
    }
    const value = styles[property];
    // eslint-disable-next-line eqeqeq
    if (value == null) {
      continue;
    }
    if (isResetValue.isResetValue(value)) {
      const selector = trimSelector.trimSelector(selectors.join(''));
      // uniq key based on a hash of property & selector, used for merging later
      const key = hashPropertyKey.hashPropertyKey(selector, property, atRules);
      pushToClassesMap(cssClassesMap, key, 0, undefined);
      continue;
    }
    if (typeof value === 'string' || typeof value === 'number') {
      const selector = trimSelector.trimSelector(selectors.join(''));
      const shorthand = getShorthandDefinition(property);
      if (shorthand) {
        const shorthandProperties = shorthand[1];
        const shorthandResetStyles = Object.fromEntries(shorthandProperties.map(property => [property, constants.RESET]));
        resolveStyleRules(shorthandResetStyles, classNameHashSalt, selectors, atRules, cssClassesMap, cssRulesByBucket);
      }
      // uniq key based on a hash of property & selector, used for merging later
      const key = hashPropertyKey.hashPropertyKey(selector, property, atRules);
      const className = hashClassName.hashClassName({
        value: value.toString(),
        salt: classNameHashSalt,
        selector,
        property
      }, atRules);
      const rtlDefinition = rtlValue && {
        key: property,
        value: rtlValue
      } || core.convertProperty(property, value);
      const flippedInRtl = rtlDefinition.key !== property || rtlDefinition.value !== value;
      const rtlClassName = flippedInRtl ? hashClassName.hashClassName({
        value: rtlDefinition.value.toString(),
        property: rtlDefinition.key,
        salt: classNameHashSalt,
        selector
      }, atRules) : undefined;
      const rtlCompileOptions = flippedInRtl ? {
        rtlClassName,
        rtlProperty: rtlDefinition.key,
        rtlValue: rtlDefinition.value
      } : undefined;
      const styleBucketName = getStyleBucketName.getStyleBucketName(selectors, atRules);
      const [ltrCSS, rtlCSS] = compileAtomicCSSRule.compileAtomicCSSRule(Object.assign({
        className,
        selectors,
        property,
        value
      }, rtlCompileOptions), atRules);
      pushToClassesMap(cssClassesMap, key, className, rtlClassName);
      pushToCSSRules(cssRulesByBucket, styleBucketName, ltrCSS, rtlCSS, atRules.media, computePropertyPriority(shorthand));
    } else if (property === 'animationName') {
      const animationNameValue = Array.isArray(value) ? value : [value];
      const animationNames = [];
      const rtlAnimationNames = [];
      for (const keyframeObject of animationNameValue) {
        const keyframeCSS = compileKeyframeCSS.compileKeyframeRule(keyframeObject);
        const rtlKeyframeCSS = compileKeyframeCSS.compileKeyframeRule(core.convert(keyframeObject));
        const animationName = constants.HASH_PREFIX + hashString__default.default(keyframeCSS);
        let rtlAnimationName;
        const keyframeRules = compileKeyframeCSS.compileKeyframesCSS(animationName, keyframeCSS);
        let rtlKeyframeRules = [];
        if (keyframeCSS === rtlKeyframeCSS) {
          // If CSS for LTR & RTL are same we will re-use animationName from LTR to avoid duplication of rules in output
          rtlAnimationName = animationName;
        } else {
          rtlAnimationName = constants.HASH_PREFIX + hashString__default.default(rtlKeyframeCSS);
          rtlKeyframeRules = compileKeyframeCSS.compileKeyframesCSS(rtlAnimationName, rtlKeyframeCSS);
        }
        for (let i = 0; i < keyframeRules.length; i++) {
          pushToCSSRules(cssRulesByBucket,
          // keyframes styles should be inserted into own bucket
          'k', keyframeRules[i], rtlKeyframeRules[i], atRules.media,
          // keyframes always have default priority
          0);
        }
        animationNames.push(animationName);
        rtlAnimationNames.push(rtlAnimationName);
      }
      resolveStyleRules({
        animationName: animationNames.join(', ')
      }, classNameHashSalt, selectors, atRules, cssClassesMap, cssRulesByBucket, rtlAnimationNames.join(', '));
    } else if (Array.isArray(value)) {
      // not animationName property but array in the value => fallback values
      if (value.length === 0) {
        if (process.env.NODE_ENV !== 'production') {
          console.warn(`makeStyles(): An empty array was passed as input to "${property}", the property will be omitted in the styles.`);
        }
        continue;
      }
      const selector = trimSelector.trimSelector(selectors.join(''));
      const shorthand = getShorthandDefinition(property);
      if (shorthand) {
        const shorthandProperties = shorthand[1];
        const shorthandResetStyles = Object.fromEntries(shorthandProperties.map(property => [property, constants.RESET]));
        resolveStyleRules(shorthandResetStyles, classNameHashSalt, selectors, atRules, cssClassesMap, cssRulesByBucket);
      }
      const key = hashPropertyKey.hashPropertyKey(selector, property, atRules);
      const className = hashClassName.hashClassName({
        value: value.map(v => (v !== null && v !== void 0 ? v : '').toString()).join(';'),
        salt: classNameHashSalt,
        selector,
        property
      }, atRules);
      const rtlDefinitions = value.map(v => core.convertProperty(property, v));
      const rtlPropertyConsistent = !rtlDefinitions.some(v => v.key !== rtlDefinitions[0].key);
      if (!rtlPropertyConsistent) {
        if (process.env.NODE_ENV !== 'production') {
          console.error('makeStyles(): mixing CSS fallback values which result in multiple CSS properties in RTL is not supported.');
        }
        continue;
      }
      const flippedInRtl = rtlDefinitions[0].key !== property || rtlDefinitions.some((v, i) => v.value !== value[i]);
      const rtlClassName = flippedInRtl ? hashClassName.hashClassName({
        value: rtlDefinitions.map(v => {
          var _a;
          return ((_a = v === null || v === void 0 ? void 0 : v.value) !== null && _a !== void 0 ? _a : '').toString();
        }).join(';'),
        salt: classNameHashSalt,
        property: rtlDefinitions[0].key,
        selector
      }, atRules) : undefined;
      const rtlCompileOptions = flippedInRtl ? {
        rtlClassName,
        rtlProperty: rtlDefinitions[0].key,
        rtlValue: rtlDefinitions.map(d => d.value)
      } : undefined;
      const styleBucketName = getStyleBucketName.getStyleBucketName(selectors, atRules);
      const [ltrCSS, rtlCSS] = compileAtomicCSSRule.compileAtomicCSSRule(Object.assign({
        className,
        selectors,
        property,
        value: value
      }, rtlCompileOptions), atRules);
      pushToClassesMap(cssClassesMap, key, className, rtlClassName);
      pushToCSSRules(cssRulesByBucket, styleBucketName, ltrCSS, rtlCSS, atRules.media, computePropertyPriority(shorthand));
    } else if (isObject.isObject(value)) {
      if (isNestedSelector.isNestedSelector(property)) {
        resolveStyleRules(value, classNameHashSalt, selectors.concat(normalizeNestedProperty.normalizeNestedProperty(property)), atRules, cssClassesMap, cssRulesByBucket);
      } else if (isMediaQuerySelector.isMediaQuerySelector(property)) {
        const combinedMediaQuery = generateCombinedMediaQuery.generateCombinedQuery(atRules.media, property.slice(6).trim());
        resolveStyleRules(value, classNameHashSalt, selectors, Object.assign({}, atRules, {
          media: combinedMediaQuery
        }), cssClassesMap, cssRulesByBucket);
      } else if (isLayerSelector.isLayerSelector(property)) {
        const combinedLayerQuery = (atRules.layer ? `${atRules.layer}.` : '') + property.slice(6).trim();
        resolveStyleRules(value, classNameHashSalt, selectors, Object.assign({}, atRules, {
          layer: combinedLayerQuery
        }), cssClassesMap, cssRulesByBucket);
      } else if (isSupportQuerySelector.isSupportQuerySelector(property)) {
        const combinedSupportQuery = generateCombinedMediaQuery.generateCombinedQuery(atRules.supports, property.slice(9).trim());
        resolveStyleRules(value, classNameHashSalt, selectors, Object.assign({}, atRules, {
          supports: combinedSupportQuery
        }), cssClassesMap, cssRulesByBucket);
      } else if (isContainerQuerySelector.isContainerQuerySelector(property)) {
        // TODO implement nested container queries if needed
        // The only way to target multiple containers is to nest container queries
        // https://developer.mozilla.org/en-US/docs/Web/CSS/@container#nested_container_queries
        const containerQuery = property.slice(10).trim();
        resolveStyleRules(value, classNameHashSalt, selectors, Object.assign({}, atRules, {
          container: containerQuery
        }), cssClassesMap, cssRulesByBucket);
      } else {
        warnAboutUnresolvedRule.warnAboutUnresolvedRule(property, value);
      }
    }
  }
  return [cssClassesMap, cssRulesByBucket];
}

exports.resolveStyleRules = resolveStyleRules;
//# sourceMappingURL=resolveStyleRules.cjs.js.map
