export const useFlatTreeContextValues_unstable = (state)=>{
    const { openItems, level, contextType, treeType, checkedItems, selectionMode, navigationMode, appearance, size, requestTreeResponse, forceUpdateRovingTabIndex } = state;
    /**
   * This context is created with "@fluentui/react-context-selector",
   * there is no sense to memoize it
   */ const tree = {
        treeType,
        size,
        openItems,
        appearance,
        checkedItems,
        selectionMode,
        navigationMode,
        contextType,
        level,
        requestTreeResponse,
        forceUpdateRovingTabIndex
    };
    return {
        tree
    };
};
