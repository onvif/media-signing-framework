import type { GriffelStyle } from '@griffel/style-types';
import type { OutlineColorInput, OutlineStyleInput, OutlineWidthInput } from './types';
type OutlineStyle = Pick<GriffelStyle, 'outlineColor' | 'outlineStyle' | 'outlineWidth'>;
/** @deprecated Use `{ outline: '2px' }` instead as Griffel supports CSS shorthands now */
export declare function outline(width: OutlineWidthInput): OutlineStyle;
/** @deprecated Use `{ outline: '2px solid' }` instead as Griffel supports CSS shorthands now */
export declare function outline(width: OutlineWidthInput, style: OutlineStyleInput): OutlineStyle;
/** @deprecated Use `{ outline: '2px solid red' }` instead as Griffel supports CSS shorthands now */
export declare function outline(width: OutlineWidthInput, style: OutlineStyleInput, color: OutlineColorInput): OutlineStyle;
export {};
