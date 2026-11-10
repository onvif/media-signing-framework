import type { GriffelStyle } from '@griffel/style-types';
import type { GridAreaInput } from './types';
type GridAreaStyle = Pick<GriffelStyle, 'gridRowStart' | 'gridRowEnd' | 'gridColumnStart' | 'gridColumnEnd'>;
export declare function isCustomIdent(value: GridAreaInput | undefined): boolean;
/** @deprecated Use `{ gridArea: '2' }` instead as Griffel supports CSS shorthands now */
export declare function gridArea(all: GridAreaInput): GridAreaStyle;
/** @deprecated Use `{ gridArea: '2 / 4' }` instead as Griffel supports CSS shorthands now */
export declare function gridArea(rowStart: GridAreaInput, columnStart: GridAreaInput): GridAreaStyle;
/** @deprecated Use `{ gridArea: '2 / 4 / 4' }` instead as Griffel supports CSS shorthands now */
export declare function gridArea(rowStart: GridAreaInput, columnStart: GridAreaInput, rowEnd: GridAreaInput): GridAreaStyle;
/** @deprecated Use `{ gridArea: '2 / 4 / 1 / 3' }` instead as Griffel supports CSS shorthands now */
export declare function gridArea(rowStart: GridAreaInput, columnStart: GridAreaInput, rowEnd: GridAreaInput, columnEnd: GridAreaInput): GridAreaStyle;
export {};
