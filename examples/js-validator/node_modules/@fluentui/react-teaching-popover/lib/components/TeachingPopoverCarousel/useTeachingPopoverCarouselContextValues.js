export function useTeachingPopoverCarouselContextValues_unstable(state) {
    const { store, value, selectPageByValue, selectPageByDirection } = state;
    const carousel = {
        store,
        value,
        selectPageByDirection,
        selectPageByValue
    };
    return {
        carousel
    };
}
