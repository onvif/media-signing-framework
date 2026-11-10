import type { GriffelStyle } from '@griffel/style-types';
import type { BorderColorInput, BorderStyleInput, BorderWidthInput } from './types';
type BorderBottomStyle = Pick<GriffelStyle, 'borderBottomColor' | 'borderBottomStyle' | 'borderBottomWidth'>;
/** @deprecated Use `{ borderBottom: '2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderBottom(width: BorderWidthInput): BorderBottomStyle;
/** @deprecated Use `{ borderBottom: 'solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderBottom(style: BorderStyleInput): BorderBottomStyle;
/** @deprecated Use `{ borderBottom: '2px solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderBottom(width: BorderWidthInput, style: BorderStyleInput): BorderBottomStyle;
/** @deprecated Use `{ borderBottom: 'solid 2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderBottom(style: BorderStyleInput, width: BorderWidthInput): BorderBottomStyle;
/** @deprecated Use `{ borderBottom: '2px solid red' }` instead as Griffel supports CSS shorthands now */
export declare function borderBottom(width: BorderWidthInput, style: BorderStyleInput, color: BorderColorInput): BorderBottomStyle;
/** @deprecated Use `{ borderBottom: 'solid 2px red' }` instead as Griffel supports CSS shorthands now */
export declare function borderBottom(style: BorderStyleInput, width: BorderWidthInput, color: BorderColorInput): BorderBottomStyle;
export {};
