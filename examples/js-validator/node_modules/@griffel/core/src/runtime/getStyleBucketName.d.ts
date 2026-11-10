import type { StyleBucketName } from '../types';
import type { AtRules } from './utils/types';
/**
 * Gets the bucket depending on the pseudo.
 *
 * Input:
 *
 * ```
 * ":hover"
 * ":focus:hover"
 * ```
 *
 * Output:
 *
 * ```
 * "h"
 * "f"
 * ```
 *
 * @internal
 */
export declare function getStyleBucketName(selectors: string[], atRules: AtRules): StyleBucketName;
