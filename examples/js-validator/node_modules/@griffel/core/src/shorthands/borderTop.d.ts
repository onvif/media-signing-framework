import type { GriffelStyle } from '@griffel/style-types';
import type { BorderColorInput, BorderStyleInput, BorderWidthInput } from './types';
type BorderTopStyle = Pick<GriffelStyle, 'borderTopColor' | 'borderTopStyle' | 'borderTopWidth'>;
/** @deprecated Use `{ borderTop: '2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderTop(width: BorderWidthInput): BorderTopStyle;
/** @deprecated Use `{ borderTop: 'solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderTop(style: BorderStyleInput): BorderTopStyle;
/** @deprecated Use `{ borderTop: '2px solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderTop(width: BorderWidthInput, style: BorderStyleInput): BorderTopStyle;
/** @deprecated Use `{ borderTop: 'solid 2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderTop(style: BorderStyleInput, width: BorderWidthInput): BorderTopStyle;
/** @deprecated Use `{ borderTop: '2px solid red' }` instead as Griffel supports CSS shorthands now */
export declare function borderTop(width: BorderWidthInput, style: BorderStyleInput, color: BorderColorInput): BorderTopStyle;
/** @deprecated Use `{ borderTop: 'solid 2px red' }` instead as Griffel supports CSS shorthands now */
export declare function borderTop(style: BorderStyleInput, width: BorderWidthInput, color: BorderColorInput): BorderTopStyle;
export {};
