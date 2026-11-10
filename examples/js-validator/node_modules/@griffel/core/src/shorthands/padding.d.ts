import type { GriffelStyle } from '@griffel/style-types';
import type { PaddingInput } from './types';
type PaddingStyle = Pick<GriffelStyle, 'paddingTop' | 'paddingRight' | 'paddingBottom' | 'paddingLeft'>;
/** @deprecated Use `{ padding: '10px' }` instead as Griffel supports CSS shorthands now */
export declare function padding(all: PaddingInput): PaddingStyle;
/** @deprecated Use `{ padding: '10px 5px' }` instead as Griffel supports CSS shorthands now */
export declare function padding(vertical: PaddingInput, horizontal: PaddingInput): PaddingStyle;
/** @deprecated Use `{ padding: '10px 5px 8px' }` instead as Griffel supports CSS shorthands now */
export declare function padding(top: PaddingInput, horizontal: PaddingInput, bottom: PaddingInput): PaddingStyle;
/** @deprecated Use `{ padding: '10px 5px 8px 4px' }` instead as Griffel supports CSS shorthands now */
export declare function padding(top: PaddingInput, right: PaddingInput, bottom: PaddingInput, left: PaddingInput): PaddingStyle;
export {};
