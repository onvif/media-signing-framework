import type { GriffelStyle } from '@griffel/style-types';
import type { FlexInput } from './types';
type FlexStyle = Pick<GriffelStyle, 'flexGrow' | 'flexShrink' | 'flexBasis'>;
/**
 * A function that implements CSS spec conformant expansion for "flex".
 *
 * @example
 *   flex('auto')
 *   flex(1, '2.5rem')
 *   flex(0, 0, 'auto')
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/CSS/flex
 *
 * @deprecated Just use `{ flex: '1 1 0' }` instead as Griffel supports CSS shorthands now
 */
export declare function flex(...values: FlexInput): FlexStyle;
export {};
