import { ImmutableMap } from './ImmutableMap';
const tuplifyCheckedItem = (value)=>Array.isArray(value) ? value : [
        value,
        true
    ];
export const createCheckedItems = (iterable)=>ImmutableMap.from(iterable, tuplifyCheckedItem);
