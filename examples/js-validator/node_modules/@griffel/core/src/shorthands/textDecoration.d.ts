import type { GriffelStyle } from '@griffel/style-types';
import type { TextDecorationColorInput, TextDecorationLineInput, TextDecorationStyleInput, TextDecorationThicknessInput } from './types';
type TextDecorationStyle = Pick<GriffelStyle, 'textDecorationStyle' | 'textDecorationLine' | 'textDecorationColor' | 'textDecorationThickness'>;
/** @deprecated Use `{ textDecoration: 'none' }` instead as Griffel supports CSS shorthands now */
export declare function textDecoration(style: TextDecorationStyleInput): TextDecorationStyle;
/** @deprecated Use `{ textDecoration: 'dotted' }` instead as Griffel supports CSS shorthands now */
export declare function textDecoration(line: TextDecorationLineInput): TextDecorationStyle;
/** @deprecated Use `{ textDecoration: 'underline dotted' }` instead as Griffel supports CSS shorthands now */
export declare function textDecoration(line: TextDecorationLineInput, style: TextDecorationStyleInput): TextDecorationStyle;
/** @deprecated Use `{ textDecoration: 'underline dotted red' }` instead as Griffel supports CSS shorthands now */
export declare function textDecoration(line: TextDecorationLineInput, style: TextDecorationStyleInput, color: TextDecorationColorInput): TextDecorationStyle;
/** @deprecated Use `{ textDecoration: 'underline dotted red 2px' }` instead as Griffel supports CSS shorthands now */
export declare function textDecoration(line: TextDecorationLineInput, style: TextDecorationStyleInput, color: TextDecorationColorInput, thickness: TextDecorationThicknessInput): TextDecorationStyle;
export {};
