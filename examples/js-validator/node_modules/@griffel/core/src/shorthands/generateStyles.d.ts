import type { GriffelStylesCSSValue, ValueOrArray, GriffelStyle } from '@griffel/style-types';
type DirectionalProperties = 'border' | 'padding' | 'margin';
export declare function generateStyles<Styles extends GriffelStyle>(property: DirectionalProperties, suffix: '' | 'Color' | 'Style' | 'Width', ...values: ValueOrArray<GriffelStylesCSSValue>[]): Styles;
export {};
