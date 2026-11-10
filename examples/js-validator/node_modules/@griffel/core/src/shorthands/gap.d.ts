import type { GriffelStyle } from '@griffel/style-types';
import type { GapInput } from './types';
type GapStyle = Pick<GriffelStyle, 'columnGap' | 'rowGap'>;
/**
 * A function that implements CSS spec conformant expansion for "gap"
 *
 * @example
 *   gap('10px')
 *   gap('10px', '5px')
 *
 * See https://developer.mozilla.org/en-US/docs/Web/CSS/gap
 *
 * @deprecated Just use `{ gap: '10px 5px' }` instead as Griffel supports CSS shorthands now
 */
export declare function gap(columnGap: GapInput, rowGap?: GapInput): GapStyle;
export {};
