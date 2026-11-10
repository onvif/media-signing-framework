import type { GriffelStyle } from '@griffel/style-types';
import type { BorderColorInput, BorderStyleInput, BorderWidthInput } from './types';
type BorderStyle = Pick<GriffelStyle, 'borderTopColor' | 'borderTopStyle' | 'borderTopWidth' | 'borderRightColor' | 'borderRightStyle' | 'borderRightWidth' | 'borderBottomColor' | 'borderBottomStyle' | 'borderBottomWidth' | 'borderLeftColor' | 'borderLeftStyle' | 'borderLeftWidth'>;
/** @deprecated Use `{ border: '2px' }` instead as Griffel supports CSS shorthands now */
export declare function border(width: BorderWidthInput): BorderStyle;
/** @deprecated Use `{ border: '2px solid' }` instead as Griffel supports CSS shorthands now */
export declare function border(width: BorderWidthInput, style: BorderStyleInput): BorderStyle;
/** @deprecated Use `{ border: '2px solid red' }` instead as Griffel supports CSS shorthands now */
export declare function border(width: BorderWidthInput, style: BorderStyleInput, color: BorderColorInput): BorderStyle;
export {};
