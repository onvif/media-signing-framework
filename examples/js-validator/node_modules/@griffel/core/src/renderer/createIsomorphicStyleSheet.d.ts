import type { IsomorphicStyleSheet, StyleBucketName } from '../types';
export declare function createIsomorphicStyleSheet(styleElement: HTMLStyleElement | undefined, bucketName: StyleBucketName, priority: number, elementAttributes: Record<string, string>): IsomorphicStyleSheet;
export declare function createIsomorphicStyleSheetFromElement(element: HTMLStyleElement): IsomorphicStyleSheet;
