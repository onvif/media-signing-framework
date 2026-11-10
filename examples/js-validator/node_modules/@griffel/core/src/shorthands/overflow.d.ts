import type { GriffelStyle } from '@griffel/style-types';
import type { OverflowInput } from './types';
type OverflowStyle = Pick<GriffelStyle, 'overflowX' | 'overflowY'>;
/**
 * A function that implements CSS spec conformant expansion for "overflow"
 *
 * @example
 *   overflow('hidden')
 *   overflow('hidden', 'scroll')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/overflow
 *
 * @deprecated Just use `{ overflow: 'hidden scroll' }` instead as Griffel supports CSS shorthands now
 */
export declare function overflow(overflowX: OverflowInput, overflowY?: OverflowInput): OverflowStyle;
export {};
