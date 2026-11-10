import type * as CSS from 'csstype';
import type { GriffelStylesCSSValue } from './shared';
type GriffelResetStylesCSSProperties = Omit<CSS.PropertiesFallback<GriffelStylesCSSValue>, 'animationName'>;
export type GriffelResetStylesStrictCSSObject = GriffelResetStylesCSSProperties & GriffelCSSPseudos & {
    animationName?: GriffelResetAnimation | GriffelResetAnimation[] | string;
};
type GriffelCSSObjectCustom = {
    [Property: string]: GriffelResetStyle | GriffelStylesCSSValue;
} & GriffelResetStylesStrictCSSObject;
type GriffelCSSPseudos = {
    [Property in CSS.Pseudos]?: GriffelResetStylesStrictCSSObject | GriffelCSSObjectCustom;
};
export type GriffelResetAnimation = Record<'from' | 'to' | string, GriffelResetStylesCSSProperties & {
    [Property in `--${string}`]: string;
}>;
export type GriffelResetStyle = GriffelResetStylesStrictCSSObject | GriffelCSSObjectCustom;
export {};
