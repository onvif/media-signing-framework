import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'lib-dist',
    lib: {
      entry: './src/true-single-file-entry.tsx',
      name: 'ONVIFVideoValidator',
      fileName: 'onvif-media-signing-verifier-file',
      formats: ['iife']
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      }
    }
  },
  define: {
    'process.env.NODE_ENV': '"production"'
  }
});
