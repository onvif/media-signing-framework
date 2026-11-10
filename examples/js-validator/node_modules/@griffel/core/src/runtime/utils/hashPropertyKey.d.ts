import type { PropertyHash } from '../../types';
import type { AtRules } from './types';
export declare function atRulesToString(atRules: AtRules): string;
export declare function hashPropertyKey(selector: string, property: string, atRules: AtRules): PropertyHash;
