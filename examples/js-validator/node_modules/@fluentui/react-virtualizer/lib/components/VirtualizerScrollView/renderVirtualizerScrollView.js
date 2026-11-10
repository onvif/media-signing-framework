  import { jsx as _jsx } from "@fluentui/react-jsx-runtime/jsx-runtime";
import { assertSlots } from '@fluentui/react-utilities';
import { renderVirtualizer_unstable } from '../Virtualizer/renderVirtualizer';
/**
 * @deprecated migrated to \@fluentui\-contrib/react\-virtualizer for stable release.
 */ export const renderVirtualizerScrollView_unstable = (state)=>{
    assertSlots(state);
    return /*#__PURE__*/ _jsx(state.container, {
        children: renderVirtualizer_unstable(state)
    });
};
