// Embeds the raw validator.js glue code and initializes the WASM module once.
// We assume validator.wasm is served from the same directory as the final bundled script.
// Strategy:
// 1. Import validator.js as string (?raw) so Vite includes it in the bundle.
// 2. Wrap it in a Function and evaluate to obtain the MODULARIZE factory (async function Module(opts)).
// 3. Provide locateFile so the wasm file is found next to the embedding script.
// 4. Cache the initialized Module (Promise) for repeated calls.

// NOTE: If validator.js was built with -s MODULARIZE=1, it exports a function (Module) returning a Promise.
// We expose ensureWasmReady() that resolves after runtime is ready.

// eslint-disable-next-line import/no-webpack-loader-syntax -- Vite handles ?raw
// @ts-ignore - using ?raw for text import
import validatorSource from '../../validator.js?raw';

// Augment global
declare global {
  interface Window {
    Module: any; // keep as any since emscripten may reassign; avoid optional to match existing ambient
    ONVIFVideoValidatorWasmReady?: boolean;
  }
}
if (!window.Module) { (window as any).Module = {}; }

let modulePromise: Promise<any> | null = null;
let resolvedModule: any = null;

function resolveScriptBase(): string {
  // Find the current executing script that includes our bundle name (heuristic)
  const scripts = Array.from(document.getElementsByTagName('script'));
  for (const s of scripts) {
    const src = s.getAttribute('src') || '';
    if (src.includes('onvif-video-validator')) {
      try {
        const url = new URL(src, window.location.href);
        return url.href.substring(0, url.href.lastIndexOf('/') + 1);
      } catch {/* ignore */}
    }
  }
  // Fallback: current location
  return window.location.href.substring(0, window.location.href.lastIndexOf('/') + 1);
}

function bootstrapFactory(overrides: Record<string, any> = {}): Promise<any> {
  // Combine overrides with locateFile resolution
  const base = resolveScriptBase();
  const opts: any = {
    locateFile: (path: string) => base + path,
    ...overrides,
  };
  const userOnRuntimeInitialized = opts.onRuntimeInitialized;
  opts.onRuntimeInitialized = function() {
    if (typeof userOnRuntimeInitialized === 'function') {
      try { userOnRuntimeInitialized(); } catch { /* ignore */ }
    }
    window.ONVIFVideoValidatorWasmReady = true;
    window.dispatchEvent(new Event('onvif-validator-wasm-ready'));
  };

  // If wasmBinary already present (e.g., provided by single-file embed) skip fetching.
  let preload: Promise<any>;
  if (opts.wasmBinary || (window.Module && window.Module.wasmBinary)) {
    if (!opts.wasmBinary && window.Module && window.Module.wasmBinary) {
      opts.wasmBinary = window.Module.wasmBinary; // reuse embedded binary ArrayBuffer
    }
    console.log('[validatorLoader] Using pre-embedded wasmBinary, skipping network fetch');
    // Ensure streaming disabled to force direct instantiation.
    try { (WebAssembly as any).instantiateStreaming = undefined; } catch { /* ignore */ }
    preload = Promise.resolve();
  } else {
    const wasmUrl = opts.locateFile('validator.wasm');
    console.log('[validatorLoader] Preloading wasm from', wasmUrl);
    preload = fetch(wasmUrl + '?cb=' + Date.now(), { cache: 'no-store' })
      .then(async (res) => {
        if (!res.ok) throw new Error('Failed to fetch wasm: ' + res.status);
        const buf = await res.arrayBuffer();
        opts.wasmBinary = buf;
        try { (WebAssembly as any).instantiateStreaming = undefined; } catch { /* ignore */ }
      });
  }

  const factory: any = (new Function(`${validatorSource}; return Module;`))();
  if (typeof factory !== 'function') {
    return Promise.reject(new Error('Unexpected validator module format'));
  }
  return preload.then(() => factory(opts)).then((m: any) => {
    resolvedModule = m;
    window.Module = m;
    if (m && m.ccall) {
      window.ONVIFVideoValidatorWasmReady = true;
      window.dispatchEvent(new Event('onvif-validator-wasm-ready'));
    }
    return m;
  });
}

export function ensureWasmReady(overrides?: Record<string, any>): Promise<any> {
  console.log('🔧 validatorLoader.ensureWasmReady() called');
  
  // Check if we're in single-file mode (embedded validator available)
  if ((window as any).ONVIFVideoValidatorModule) {
    console.log('✅ Found ONVIFVideoValidatorModule, using single-file mode');
    resolvedModule = (window as any).ONVIFVideoValidatorModule;
    if (!window.ONVIFVideoValidatorWasmReady) {
      window.ONVIFVideoValidatorWasmReady = true;
      window.dispatchEvent(new Event('onvif-validator-wasm-ready'));
      console.log('✅ Set ready flag and dispatched event');
    }
    return Promise.resolve(resolvedModule);
  }

  console.log('📦 Using regular two-file mode');
  if (resolvedModule) return Promise.resolve(resolvedModule);
  if (!modulePromise) {
    modulePromise = bootstrapFactory(overrides);
  }
  return modulePromise.then(m => {
    if (!window.ONVIFVideoValidatorWasmReady && m && m.ccall) {
      window.ONVIFVideoValidatorWasmReady = true;
      window.dispatchEvent(new Event('onvif-validator-wasm-ready'));
    }
    return m;
  });
}
