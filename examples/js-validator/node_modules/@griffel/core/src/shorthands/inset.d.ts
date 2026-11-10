import type { GriffelStyle } from '@griffel/style-types';
import type { InsetInput } from './types';
type InsetStyle = Pick<GriffelStyle, 'top' | 'right' | 'bottom' | 'left'>;
/** @deprecated Use `{ inset: '10px' }` instead as Griffel supports CSS shorthands now */
export declare function inset(all: InsetInput): InsetStyle;
/** @deprecated Use `{ inset: '10px 5px' }` instead as Griffel supports CSS shorthands now */
export declare function inset(vertical: InsetInput, horizontal: InsetInput): InsetStyle;
/** @deprecated Use `{ inset: '10px 5px 8px' }` instead as Griffel supports CSS shorthands now */
export declare function inset(top: InsetInput, horizontal: InsetInput, bottom: InsetInput): InsetStyle;
/** @deprecated Use `{ inset: '10px 5px 8px 4px' }` instead as Griffel supports CSS shorthands now */
export declare function inset(top: InsetInput, right: InsetInput, bottom: InsetInput, left: InsetInput): InsetStyle;
export {};
