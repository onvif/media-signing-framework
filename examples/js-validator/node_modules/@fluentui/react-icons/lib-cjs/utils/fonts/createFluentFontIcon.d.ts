import * as React from 'react';
import { FluentIconsProps } from '../FluentIconsProps.types';
import { FontFile } from './createFluentFontIcon.shared';
export declare type CreateFluentFontIconOptions = {
    flipInRtl?: boolean;
};
export declare type FluentFontIcon = React.FC<FluentIconsProps<React.HTMLAttributes<HTMLElement>, HTMLElement>> & {
    codepoint: string;
};
export declare function createFluentFontIcon(displayName: string, codepoint: string, font: FontFile, fontSize?: number, options?: CreateFluentFontIconOptions): FluentFontIcon;
