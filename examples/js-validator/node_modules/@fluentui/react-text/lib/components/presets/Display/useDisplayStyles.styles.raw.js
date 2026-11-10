import { makeStyles } from '@griffel/react';
import { typographyStyles } from '@fluentui/react-theme';
export const displayClassNames = {
    root: 'fui-Display'
};
/**
 * Styles for the root slot
 */ export const useDisplayStyles = makeStyles({
    root: typographyStyles.display
});
