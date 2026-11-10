import React from 'react';
import { makeStyles } from '@fluentui/react-components';
import { useScrollStaticStyles } from '../fluent-components/styles/src/index.js';
import VideoValidator from './VideoValidator';

const useAppStyles = makeStyles({
  validatorAppContainer: {
    maxWidth: '1300px',
    margin: '0 auto',
    alignContent: 'center'
  },
});

const App: React.FC = () => {
  const styles = useAppStyles();
  useScrollStaticStyles();

  return (
    <div className={styles.validatorAppContainer}>
      <VideoValidator />
    </div>
  );
};

export default App;
