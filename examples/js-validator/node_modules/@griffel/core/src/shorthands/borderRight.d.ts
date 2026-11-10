import type { GriffelStyle } from '@griffel/style-types';
import type { BorderColorInput, BorderStyleInput, BorderWidthInput } from './types';
type BorderRightStyle = Pick<GriffelStyle, 'borderRightWidth' | 'borderRightStyle' | 'borderRightColor'>;
/** @deprecated Use `{ borderRight: '2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderRight(width: BorderWidthInput): BorderRightStyle;
/** @deprecated Use `{ borderRight: 'solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderRight(style: BorderStyleInput): BorderRightStyle;
/** @deprecated Use `{ borderRight: '2px solid' }` instead as Griffel supports CSS shorthands now */
export declare function borderRight(width: BorderWidthInput, style: BorderStyleInput): BorderRightStyle;
/** @deprecated Use `{ borderRight: 'solid 2px' }` instead as Griffel supports CSS shorthands now */
export declare function borderRight(style: BorderStyleInput, width: BorderWidthInput): BorderRightStyle;
/** @deprecated Use `{ borderRight: '2px solid red' }` instead as Griffel supports CSS shorthands now */
export declare function borderRight(width: BorderWidthInput, style: BorderStyleInput, color: BorderColorInput): BorderRightStyle;
/** @deprecated Use `{ borderRight: 'solid 2px red' }` instead as Griffel supports CSS shorthands now */
export declare function borderRight(style: BorderStyleInput, width: BorderWidthInput, color: BorderColorInput): BorderRightStyle;
export {};
