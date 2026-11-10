import type * as CSS from 'csstype';
import type { GriffelStylesUnsupportedCSSProperties } from '@griffel/style-types';
type AllowedShorthandProperties = keyof Omit<CSS.Properties, keyof GriffelStylesUnsupportedCSSProperties>;
export declare const shorthands: Partial<Record<AllowedShorthandProperties, [number, string[]]>>;
export {};
