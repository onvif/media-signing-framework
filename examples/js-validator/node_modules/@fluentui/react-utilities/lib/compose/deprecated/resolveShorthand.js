import * as slot from '../slot';
/**
 *
 * Resolves shorthands into slot props, to ensure normalization of the signature
 * being passed down to getSlots method
 * @param value - the base shorthand props
 * @param options - options to resolve shorthand props
 *
 * @deprecated use slot.always, slot.optional, slot.resolveShorthand combined with assertSlots instead
 */ // eslint-disable-next-line @typescript-eslint/no-deprecated
export const resolveShorthand = (value, options)=>slot.optional(value, {
        ...options,
        renderByDefault: options === null || options === void 0 ? void 0 : options.required,
        // elementType as undefined is the way to identify between a slot and a resolveShorthand call
        // in the case elementType is undefined assertSlots will fail, ensuring it'll only work with slot method.
        elementType: undefined
    });
