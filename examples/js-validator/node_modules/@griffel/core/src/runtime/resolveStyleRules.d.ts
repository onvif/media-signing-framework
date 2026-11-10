import type { GriffelStyle } from '@griffel/style-types';
import type { CSSClassesMap, CSSRulesByBucket } from '../types';
import type { AtRules } from './utils/types';
/**
 * Transforms input styles to classes maps & CSS rules.
 *
 * @internal
 */
export declare function resolveStyleRules(styles: GriffelStyle, classNameHashSalt?: string, selectors?: string[], atRules?: AtRules, cssClassesMap?: CSSClassesMap, cssRulesByBucket?: CSSRulesByBucket, rtlValue?: string): [CSSClassesMap, CSSRulesByBucket];
