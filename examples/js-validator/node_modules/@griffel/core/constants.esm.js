// ----
// Heads up!
// These constants are global and will be shared between Griffel instances.
// Any change in them should happen only in a MAJOR version. If it happens,
// please change "__NAMESPACE_PREFIX__" to include a version.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const __GLOBAL__ = typeof window === 'undefined' ? global : window;
const __NAMESPACE_PREFIX__ = '@griffel/';
function getGlobalVar(name, defaultValue) {
  if (!__GLOBAL__[Symbol.for(__NAMESPACE_PREFIX__ + name)]) {
    __GLOBAL__[Symbol.for(__NAMESPACE_PREFIX__ + name)] = defaultValue;
  }
  return __GLOBAL__[Symbol.for(__NAMESPACE_PREFIX__ + name)];
}
/** @internal */
const DEBUG_RESET_CLASSES = /*#__PURE__*/getGlobalVar('DEBUG_RESET_CLASSES', {});
/** @internal */
const DEFINITION_LOOKUP_TABLE = /*#__PURE__*/getGlobalVar('DEFINITION_LOOKUP_TABLE', {});
// ----
/** @internal */
const DATA_BUCKET_ATTR = 'data-make-styles-bucket';
/** @internal */
const DATA_PRIORITY_ATTR = 'data-priority';
/** @internal */
const HASH_PREFIX = 'f';
/** @internal */
const RESET_HASH_PREFIX = 'r';
/** @internal */
const SEQUENCE_HASH_LENGTH = 7;
/** @internal */
const SEQUENCE_PREFIX = '___';
/** @internal */
const DEBUG_SEQUENCE_SEPARATOR = '_';
/** @internal */
const SEQUENCE_SIZE = process.env.NODE_ENV === 'production' ? SEQUENCE_PREFIX.length + SEQUENCE_HASH_LENGTH : SEQUENCE_PREFIX.length + SEQUENCE_HASH_LENGTH + DEBUG_SEQUENCE_SEPARATOR.length + SEQUENCE_HASH_LENGTH;
// indexes for values in LookupItem tuple
/** @internal */
const LOOKUP_DEFINITIONS_INDEX = 0;
/** @internal */
const LOOKUP_DIR_INDEX = 1;
// This collection is a map simply for faster access when checking if a CSS property is unsupported
/** @internal */
const UNSUPPORTED_CSS_PROPERTIES = {
  all: 1,
  borderColor: 1,
  borderStyle: 1,
  borderWidth: 1,
  borderBlock: 1,
  borderBlockEnd: 1,
  borderBlockStart: 1,
  borderInline: 1,
  borderInlineEnd: 1,
  borderInlineStart: 1
};
/**
 * Removes a CSS property from the style object.
 *
 * @link https://griffel.js.org/react/api/make-styles
 *
 * Do not use the value directly, use `RESET` constant instead.
 */
const RESET = 'DO_NOT_USE_DIRECTLY: @griffel/reset-value';

export { DATA_BUCKET_ATTR, DATA_PRIORITY_ATTR, DEBUG_RESET_CLASSES, DEBUG_SEQUENCE_SEPARATOR, DEFINITION_LOOKUP_TABLE, HASH_PREFIX, LOOKUP_DEFINITIONS_INDEX, LOOKUP_DIR_INDEX, RESET, RESET_HASH_PREFIX, SEQUENCE_HASH_LENGTH, SEQUENCE_PREFIX, SEQUENCE_SIZE, UNSUPPORTED_CSS_PROPERTIES };
//# sourceMappingURL=constants.esm.js.map
