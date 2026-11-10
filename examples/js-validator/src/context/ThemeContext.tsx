import { createContext, useContext, useState, ReactNode } from 'react';
import { FluentProvider } from '@fluentui/react-components';
import { 
  axisLightTheme,
  axisDarkTheme,
  axisBlueLightTheme, 
  axisBlueDarkTheme
} from '../theme/axisTheme';

interface ThemeContextType {
  currentTheme: string;
  setTheme: (themeName: string) => void;
  availableThemes: { key: string; name: string; theme: any }[];
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [currentTheme, setCurrentTheme] = useState('axisLightTheme');
  
  const availableThemes = [
    { key: 'axisLightTheme', name: '🌞 Light', theme: axisLightTheme },
    { key: 'axisDarkTheme', name: '🌙 Dark', theme: axisDarkTheme },
    { key: 'axisBlueLightTheme', name: '🔵 Blue Light', theme: axisBlueLightTheme },
    { key: 'axisBlueDarkTheme', name: '🔷 Blue Dark', theme: axisBlueDarkTheme },
  ];

  const setTheme = (themeName: string) => {
    setCurrentTheme(themeName);
  };

  const currentThemeObj = availableThemes.find(t => t.key === currentTheme)?.theme || axisLightTheme;

  return (
    <ThemeContext.Provider value={{ currentTheme, setTheme, availableThemes }}>
      <FluentProvider theme={currentThemeObj}>
        {children}
      </FluentProvider>
    </ThemeContext.Provider>
  );
}
