import type * as CSS from 'csstype';
import type { Fallback, GriffelStylesCSSValue } from '../shared';
import type { GriffelStylesUnsupportedCSSProperties } from '../unsupported-properties';
type GriffelStylesCSSProperties = Omit<Fallback<CSS.Properties<GriffelStylesCSSValue>>, 'animationName'> & Partial<GriffelStylesUnsupportedCSSProperties>;
export type GriffelStylesStrictCSSObject = GriffelStylesCSSProperties & GriffelStylesCSSPseudos & {
    animationName?: GriffelAnimation | GriffelAnimation[] | CSS.Property.Animation;
};
type GriffelStylesCSSPseudos = {
    [Property in CSS.Pseudos]?: (GriffelStylesStrictCSSObject & {
        content?: string | string[];
    }) | (GriffelStylesCSSObjectCustomL1 & {
        content?: string | string[];
    });
};
type GriffelStylesCSSObjectCustomL1 = {
    [Property: string]: string | number | (string | number)[] | undefined | GriffelStylesCSSObjectCustomL2;
} & GriffelStylesStrictCSSObject;
type GriffelStylesCSSObjectCustomL2 = {
    [Property: string]: string | number | (string | number)[] | undefined | GriffelStylesCSSObjectCustomL3;
} & GriffelStylesStrictCSSObject;
type GriffelStylesCSSObjectCustomL3 = {
    [Property: string]: string | number | (string | number)[] | undefined | GriffelStylesCSSObjectCustomL4;
} & GriffelStylesStrictCSSObject;
type GriffelStylesCSSObjectCustomL4 = {
    [Property: string]: string | number | (string | number)[] | undefined | GriffelStylesCSSObjectCustomL5;
} & GriffelStylesStrictCSSObject;
type GriffelStylesCSSObjectCustomL5 = {
    [Property: string]: string | number | (string | number)[] | undefined | GriffelStylesStrictCSSObject;
} & GriffelStylesStrictCSSObject;
export type GriffelStyle = GriffelStylesStrictCSSObject | GriffelStylesCSSObjectCustomL1;
export type GriffelAnimation = Record<'from' | 'to' | string, GriffelStylesCSSObjectCustomL1>;
export {};
