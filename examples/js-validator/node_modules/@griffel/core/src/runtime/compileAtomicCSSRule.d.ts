import type { AtRules } from './utils/types';
export interface CompileAtomicCSSOptions {
    className: string;
    selectors: string[];
    property: string;
    value: number | string | Array<number | string>;
    rtlClassName?: string;
    rtlProperty?: string;
    rtlValue?: number | string | Array<number | string>;
}
/**
 * Normalizes pseudo selectors to always contain &, requires to work properly with comma-separated selectors.
 *
 * @example
 *   ":hover" => "&:hover"
 *   " :hover" => "& :hover"
 *   ":hover,:focus" => "&:hover,&:focus"
 *   " :hover, :focus" => "& :hover,& :focus"
 */
export declare function normalizePseudoSelector(pseudoSelector: string): string;
export declare function compileAtomicCSSRule(options: CompileAtomicCSSOptions, atRules: AtRules): [string?, string?];
