import type { AtRules } from './types';
interface HashedClassNameParts {
    property: string;
    value: string;
    salt: string;
    selector: string;
}
export declare function hashClassName({ property, selector, salt, value }: HashedClassNameParts, atRules: AtRules): string;
export {};
