import React from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from './context/ThemeContext';
import App from './App';

// Import the true single-file WASM (with embedded binary) as raw text
// eslint-disable-next-line import/no-webpack-loader-syntax
// @ts-ignore
import validatorSingleJsSource from '../validator.single.js?raw';

let wasmInitPromise: Promise<any> | null = null;
let resolvedModule: any = null;

// Load and initialize the embedded WASM
async function initValidatorFromEmbedded(overrides: Record<string, any> = {}): Promise<any> {
  if (resolvedModule) {
    return resolvedModule;
  }

  if (wasmInitPromise) {
    return wasmInitPromise;
  }

  wasmInitPromise = new Promise(async (resolve, reject) => {
    try {
      // Execute the validator.single.js source to get the Module factory
      // This already has the WASM binary embedded via Emscripten SINGLE_FILE=1
      const func = new Function('window', 'document', `
        ${validatorSingleJsSource}
        return (typeof Module !== 'undefined') ? Module : (typeof window !== 'undefined' && window.Module);
      `);
      
      const ModuleFactory = func(window, document);
      
      if (!ModuleFactory || typeof ModuleFactory !== 'function') {
        throw new Error('Module factory not found in embedded single-file validator source');
      }

      // Initialize the module - no wasmBinary needed as it's embedded in the JS
      const module = await ModuleFactory({
        ...overrides
      });
      
      resolvedModule = module;
      
      // Set globals for compatibility
      (window as any).ONVIFVideoValidatorModule = module;
      if (!window.Module) {
        window.Module = module;
      }
      (window as any).ONVIFVideoValidatorWasmReady = true;
      
      // Dispatch event
      window.dispatchEvent(new Event('onvif-validator-wasm-ready'));
      
      resolve(module);
      
    } catch (error) {
      console.error('❌ Failed to initialize embedded validator:', error);
      reject(error);
    }
  });

  return wasmInitPromise;
}

// Export the true single-file API
export async function init(selector: string | HTMLElement = 'validator-app', overrides?: Record<string, any>) {
  // Find the container element first
  let container: HTMLElement | null = null;
  if (typeof selector === 'string') {
    container = document.getElementById(selector) || document.querySelector(selector);
  } else {
    container = selector;
  }
  
  if (!container) {
    console.error(`ONVIF Media Signing Verifier: Element with selector/id "${selector}" not found`);
    return;
  }

  // Show loading state
  container.innerHTML = '<div style="padding:2rem;text-align:center;color:#666;font-family:sans-serif">🔄 Loading validator...</div>';

  // Initialize the embedded WASM validator
  try {
    await initValidatorFromEmbedded(overrides);
  } catch (e) {
    console.error('❌ ONVIF Media Signing Verifier script: Failed to initialize', e);
    container.innerHTML = `
      <div style="color:red;padding:1rem;font-family:sans-serif;border:1px solid #fcc;background:#fee;border-radius:4px;">
        <strong>⚠️ Failed to initialize validator</strong><br>
        <small>Error: ${e instanceof Error ? e.message : 'Unknown error'}</small><br>
        <button onclick="location.reload()" style="margin-top:8px;padding:4px 8px;cursor:pointer;">Retry</button>
      </div>
    `;
    return;
  }

  // Render the React application
  try {
    const root = createRoot(container);
    root.render(
      <React.StrictMode>
        <ThemeProvider>
          <App />
        </ThemeProvider>
      </React.StrictMode>
    );

  } catch (e) {
    console.error('❌ Failed to render ONVIF Media Signing Verifier application:', e);
    container.innerHTML = `
      <div style="color:red;padding:1rem;font-family:sans-serif;border:1px solid #fcc;background:#fee;border-radius:4px;">
        <strong>⚠️ Failed to render application</strong><br>
        <small>Error: ${e instanceof Error ? e.message : 'Unknown error'}</small>
      </div>
    `;
  }
}

// Also expose the WASM module directly for advanced usage
export async function getValidatorModule(overrides?: Record<string, any>) {
  return initValidatorFromEmbedded(overrides || {});
}

// Auto-initialize if a specific element exists
if (typeof window !== 'undefined') {
  // Auto-init on DOMContentLoaded if default container exists
  function autoInit() {
    const defaultContainer = document.getElementById('validator-app') || document.querySelector('[data-validator-app]');
    if (defaultContainer) {
      init(defaultContainer);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoInit);
  } else {
    // DOM already loaded
    setTimeout(autoInit, 0);
  }

  // Global assignment for script tag usage
  (window as any).ONVIFVideoValidatorTrueSingleFile = { init, getValidatorModule };
}
