// Single-file WASM loader that uses the globally available embedded validator
// This version doesn't need to load external files since everything is embedded

declare global {
  interface Window {
    ONVIFVideoValidatorModule?: any;
  }
}

let modulePromise: Promise<any> | null = null;
let resolvedModule: any = null;

export async function ensureWasmReady(_overrides: Record<string, any> = {}): Promise<any> {
  // In single-file mode, the module should already be available globally
  if (resolvedModule) {
    return resolvedModule;
  }

  if (modulePromise) {
    return modulePromise;
  }

  // Check if the module is already available globally (embedded case)
  if (window.ONVIFVideoValidatorModule) {
    resolvedModule = window.ONVIFVideoValidatorModule;
    return resolvedModule;
  }

  // If we're in a single-file build, the validator should be embedded
  // This fallback shouldn't normally be needed
  modulePromise = new Promise((resolve, reject) => {
    // Wait a bit for the embedded module to initialize
    const checkInterval = setInterval(() => {
      if (window.ONVIFVideoValidatorModule) {
        clearInterval(checkInterval);
        resolvedModule = window.ONVIFVideoValidatorModule;
        resolve(resolvedModule);
      }
    }, 50);

    // Timeout after 10 seconds
    setTimeout(() => {
      clearInterval(checkInterval);
      reject(new Error('Embedded WASM module not found - single-file build may be incomplete'));
    }, 10000);
  });

  return modulePromise;
}

// Compatibility function for existing code
export function getModule(): any {
  if (!resolvedModule) {
    throw new Error('WASM module not initialized. Call ensureWasmReady() first.');
  }
  return resolvedModule;
}

// For single-file builds, we can also provide direct access to validation functions
export async function validateNalu(unit: Uint8Array, codecType: number = 1): Promise<boolean> {
  const module = await ensureWasmReady();
  
  // Allocate memory for the unit
  const unitPtr = module._malloc(unit.length);
  if (!unitPtr) {
    throw new Error('Failed to allocate memory for NALU/OBU');
  }

  try {
    // Copy data to WASM memory
    module.HEAPU8.set(unit, unitPtr);
    
    // Call the validation function
    const result = module._oms_validate_nalu(unitPtr, unit.length, codecType);
    return result === 1;
  } finally {
    // Clean up
    module._free(unitPtr);
  }
}

export async function getFinalVerdict(): Promise<boolean> {
  const module = await ensureWasmReady();
  const result = module._oms_get_final_verdict();
  return result === 1;
}

export async function getReport(): Promise<string> {
  const module = await ensureWasmReady();
  const reportPtr = module._oms_get_report_str();
  return module.UTF8ToString(reportPtr);
}

export async function resetValidator(): Promise<void> {
  const module = await ensureWasmReady();
  module._oms_reset();
}

export async function freeValidator(): Promise<void> {
  const module = await ensureWasmReady();
  module._oms_free();
}
