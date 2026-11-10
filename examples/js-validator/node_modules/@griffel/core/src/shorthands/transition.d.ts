import type { GriffelStyle } from '@griffel/style-types';
import type { TransitionDelayInput, TransitionDurationInput, TransitionPropertyInput, TransitionTimingFunctionInput, TransitionGlobalInput } from './types';
type TransitionInputs = [
    TransitionPropertyInput,
    TransitionDurationInput?,
    TransitionDelayInput?,
    TransitionTimingFunctionInput?
];
type TransitionStyle = Pick<GriffelStyle, 'transitionProperty' | 'transitionDelay' | 'transitionDuration' | 'transitionTimingFunction'>;
/** @deprecated Use `{ transition: 'inherit' }` instead as Griffel supports CSS shorthands now */
export declare function transition(globalValue: TransitionGlobalInput): TransitionStyle;
/** @deprecated Use `{ transition: 'margin-right 4s' }` instead as Griffel supports CSS shorthands now */
export declare function transition(property: TransitionPropertyInput, duration: TransitionDurationInput): TransitionStyle;
/** @deprecated Use `{ transition: 'margin-right 4s 1s' }` instead as Griffel supports CSS shorthands now */
export declare function transition(property: TransitionPropertyInput, duration: TransitionDurationInput, delay: TransitionDelayInput): TransitionStyle;
/** @deprecated Use `{ transition: 'margin-right 4s 1s ease-in' }` instead as Griffel supports CSS shorthands now */
export declare function transition(property: TransitionPropertyInput, duration: TransitionDurationInput, delay: TransitionDelayInput, easingFunction: TransitionTimingFunctionInput): TransitionStyle;
/**
 * @deprecated Use `{ transition: 'margin-right 4s 1s ease-in, padding 3s 2s ease-out' }` instead as Griffel supports CSS shorthands now
 * */
export declare function transition(values: TransitionInputs[]): TransitionStyle;
export {};
