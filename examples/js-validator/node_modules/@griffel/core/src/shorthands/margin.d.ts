import type { GriffelStyle } from '@griffel/style-types';
import type { MarginInput } from './types';
type MarginStyle = Pick<GriffelStyle, 'marginTop' | 'marginRight' | 'marginBottom' | 'marginLeft'>;
/** @deprecated Use `{ margin: '10px 5px 8px 4px' }` instead as Griffel supports CSS shorthands now */
export declare function margin(all: MarginInput): MarginStyle;
/** @deprecated Use `{ margin: '10px 5px' }` instead as Griffel supports CSS shorthands now */
export declare function margin(vertical: MarginInput, horizontal: MarginInput): MarginStyle;
/** @deprecated Use `{ margin: '10px 5px 8px' }` instead as Griffel supports CSS shorthands now */
export declare function margin(top: MarginInput, horizontal: MarginInput, bottom: MarginInput): MarginStyle;
/** @deprecated Use `{ margin: '10px 5px 8px 4px' }` instead as Griffel supports CSS shorthands now */
export declare function margin(top: MarginInput, right: MarginInput, bottom: MarginInput, left: MarginInput): MarginStyle;
export {};
