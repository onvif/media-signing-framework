import { SLOT_CLASS_NAME_PROP_SYMBOL, SLOT_ELEMENT_TYPE_SYMBOL, SLOT_RENDER_FUNCTION_SYMBOL } from '@fluentui/react-utilities';
/**
 * @internal
 */ export function getMetadataFromSlotComponent(type) {
    const { as, [SLOT_CLASS_NAME_PROP_SYMBOL]: _classNameProp, [SLOT_ELEMENT_TYPE_SYMBOL]: baseElementType, [SLOT_RENDER_FUNCTION_SYMBOL]: renderFunction, ...propsWithoutMetadata } = type;
    const props = propsWithoutMetadata;
    const elementType = typeof baseElementType === 'string' ? as !== null && as !== void 0 ? as : baseElementType : baseElementType;
    if (typeof elementType !== 'string' && as) {
        props.as = as;
    }
    return {
        elementType,
        props,
        renderFunction
    };
}
