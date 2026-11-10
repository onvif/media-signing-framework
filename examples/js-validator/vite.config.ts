import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    port: 3000,
    watch: {
      // Exclude large dependency directories to prevent file watcher limits (ENOSPC)
      ignored: [
        '**/node_modules/**', 
        '**/dist/**', 
        '**/lib-dist/**',
        // Emscripten test files that cause issues
        '**/test/**/*.html',
        '**/corpora/**',
        '**/fuzz/**',
        // Specific problematic files
        '**/main_js_with_loader.html',
        '**/pthread/**'
      ]
    },
    fs: {
      allow: ['..']
    }
  },
  build: {
    outDir: 'dist'
  },
  // Only include source files in the dev server
  root: '.',
  resolve: {
    alias: {
      '@': '/src'
    }
  }
})
