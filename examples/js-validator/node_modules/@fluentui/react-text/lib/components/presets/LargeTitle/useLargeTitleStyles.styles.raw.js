import { makeStyles } from '@griffel/react';
import { typographyStyles } from '@fluentui/react-theme';
export const largeTitleClassNames = {
    root: 'fui-LargeTitle'
};
/**
 * Styles for the root slot
 */ export const useLargeTitleStyles = makeStyles({
    root: typographyStyles.largeTitle
});
