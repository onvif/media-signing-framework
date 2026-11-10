import type * as CSS from 'csstype';
import type { GriffelStylesCSSValue, Fallback } from './shared';
export type GriffelStaticStyle = {
    [key: string]: (CSS.Properties | Fallback<CSS.Properties<GriffelStylesCSSValue>>) & Record<string, any>;
} & {
    '@font-face'?: {
        fontFamily: string;
        src: string;
        fontDisplay?: string;
        fontFeatureSettings?: string;
        fontStretch?: string;
        fontStyle?: string;
        fontVariant?: string;
        fontVariationSettings?: string;
        fontWeight?: number | string;
        unicodeRange?: string;
    };
};
export type GriffelStaticStyles = GriffelStaticStyle | string;
