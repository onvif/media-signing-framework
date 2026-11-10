import type { GriffelStyle } from '@griffel/style-types';
import type { BorderColorInput, BorderStyleInput, BorderWidthInput } from './types';
type BorderLeftStyle = Pick<GriffelStyle, 'borderLeftColor' | 'borderLeftStyle' | 'borderLeftWidth'>;
/** @deprecated Use `{ borderLeft: '2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderLeft(width: BorderWidthInput): BorderLeftStyle;
/** @deprecated Use `{ borderLeft: 'solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderLeft(style: BorderStyleInput): BorderLeftStyle;
/** @deprecated Use `{ borderLeft: '2px solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderLeft(width: BorderWidthInput, style: BorderStyleInput): BorderLeftStyle;
/** @deprecated Use `{ borderLeft: 'solid 2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderLeft(style: BorderStyleInput, width: BorderWidthInput): BorderLeftStyle;
/** @deprecated Use `{ borderLeft: '2px solid red' }` instead as Griffel supports CSS shorthands now */
export declare function borderLeft(width: BorderWidthInput, style: BorderStyleInput, color: BorderColorInput): BorderLeftStyle;
/** @deprecated Use `{ borderLeft: 'solid 2px red' }` instead as Griffel supports CSS shorthands now */
export declare function borderLeft(style: BorderStyleInput, width: BorderWidthInput, color: BorderColorInput): BorderLeftStyle;
export {};
