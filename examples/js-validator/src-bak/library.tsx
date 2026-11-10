import React from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from './context/ThemeContext';
import App from './App';
// NEW: internal wasm loader (validator.js embedded via ?raw)
import { ensureWasmReady } from './wasm/validatorLoader';

// Cache a single wasm/module init promise so multiple init calls don't race
let wasmInitPromise: Promise<any> | null = null;
function prepareWasm(overrides?: Record<string, any>) {
  if (!wasmInitPromise) {
    wasmInitPromise = ensureWasmReady(overrides);
  }
  return wasmInitPromise;
}

// Library API: Export init function for external usage
export async function init(selector: string | HTMLElement = 'validator-app', overrides?: Record<string, any>) {
  // 1. Ensure WASM module is fully ready before rendering React
  try {
    await prepareWasm(overrides);
  } catch (e) {
    console.error('❌ ONVIF Media Signing Verifier: WASM failed to initialize', e);
    if (typeof selector === 'string') {
      const el = document.getElementById(selector) || document.querySelector(selector);
      if (el) {
        (el as HTMLElement).innerHTML = '<div style="color:red;padding:1rem;font-family:sans-serif">Failed to initialize WASM module</div>';
      }
    }
    return;
  }

  let container: HTMLElement | null = null;
  if (typeof selector === 'string') {
    container = document.getElementById(selector) || document.querySelector(selector);
  } else {
    container = selector;
  }
  if (!container) {
    console.error(`❌ ONVIF Media Signing Verifier: Element with selector/id "${selector}" not found`);
    return;
  }

  const root = createRoot(container);
  root.render(
    <React.StrictMode>
      <ThemeProvider>
        <App />
      </ThemeProvider>
    </React.StrictMode>
  );
  console.log('ONVIF Media Signing Verifier initialized (WASM ready)');
  return root;
}

// Export as default for library usage
export default { init };
