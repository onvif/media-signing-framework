import { useState, useCallback } from 'react';
import MP4Box from 'mp4box';

interface ValidationResult {
  codec: string;
  message: string;
  verdict: string;
  details?: string;
  frameCount?: number;
}

interface ValidationState {
  progress: number;
  status: 'idle' | 'validating' | 'success' | 'error';
  result: ValidationResult | null;
  report: string | null;
}

function extractNALUsFromLengthPrefixed(buffer: Uint8Array): Uint8Array[] {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let offset = 0;
  const nalus: Uint8Array[] = [];
  
  while (offset < buffer.byteLength) {
    const naluLength = view.getUint32(offset);
    offset += 4;
    const nalu = buffer.subarray(offset, offset + naluLength);
    nalus.push(nalu);
    offset += naluLength;
  }
  
  return nalus;
}

function extractOBUsFromFrame(buffer: Uint8Array): Uint8Array[] {
  // The |buffer| includes all OBUs of one frame. Read the OBU Size fields and split
  // it into separate OBUs.
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let offset = 0;
  const obus: Uint8Array[] = [];
  
  while (offset < buffer.byteLength) {
    const obuHeader = view.getUint8(offset);
    if ((obuHeader & 0x02) === 0) {  // Use correct logic with parentheses
      // The size field shall be set for ONVIF AV1 streams.
      console.log("Non-ONVIF AV1 recording detected. Abort!");
      break;
    }
    
    // Get OBU size.
    let sizeByte = view.getUint8(offset + 1);
    let obuLength = (sizeByte & 0x7F);
    let shiftBits = 7;
    
    while ((sizeByte & 0x80) !== 0) {
      sizeByte = view.getUint8(offset + 1 + (shiftBits / 7));
      obuLength += (sizeByte & 0x7F) << shiftBits;
      shiftBits += 7;
    }

    const totObuLength = 1 + (shiftBits / 7) + obuLength;
    const obu = buffer.subarray(offset, offset + totObuLength);
    obus.push(obu);
    offset += totObuLength;
  }
  
  return obus;
}

// Helper to await WASM readiness (used when user triggers validation before init finishes)
async function waitForWasmReady(timeoutMs = 10000) {
  // Check for both global Module locations (single-file vs regular builds)
  const module = (window as any).ONVIFVideoValidatorModule || window.Module;
  
  if (typeof window !== 'undefined' && module && module.ccall) {
    return;
  }
  
  console.log('WASM not ready, waiting for onvif-validator-wasm-ready event...');
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.error('❌ WASM init timeout after', timeoutMs, 'ms');
      reject(new Error('WASM init timeout'));
    }, timeoutMs);
    
    window.addEventListener('onvif-validator-wasm-ready', () => {
      console.log('✅ Received onvif-validator-wasm-ready event');
      clearTimeout(timeout);
      resolve();
    }, { once: true });
  });
}

// Helper to get the active WASM module
function getWasmModule(): any {
  const axisModule = (window as any).ONVIFVideoValidatorModule;
  const regularModule = window.Module;
  
  const module = axisModule || regularModule;
  if (!module) {
    console.error('❌ No WASM module found in window');
  }
  
  return module;
}

declare global {
  interface Window {
    Module: any;
  }
}

interface ValidationState {
  progress: number;
  status: 'idle' | 'validating' | 'success' | 'error';
  result: ValidationResult | null;
  report: string | null;
}

export function useVideoValidation() {
  const [state, setState] = useState<ValidationState>({
    progress: 0,
    status: 'idle',
    result: null,
    report: null,
  });
  
  const reset = useCallback(() => {
    setState({
      progress: 0,
      status: 'idle',
      result: null,
      report: null,
    });
    
    // Reset WASM module if available
    const module = getWasmModule();
    if (module && module.ccall) {
      try {
        module.ccall('oms_reset', 'void', [], []);
      } catch (error) {
        console.warn('Failed to reset WASM module:', error);
      }
    }
  }, []);

  const validateVideo = useCallback(async (file: File, pemFile: File | null) => {
    // Wait for WASM if not yet ready
    let module = getWasmModule();
    if (!module || !module.ccall) {
      console.log('⏳ WASM module not ready, waiting...');
      try {
        await waitForWasmReady();
        module = getWasmModule();
        console.log('✅ WASM module ready after waiting');
      } catch (e) {
        console.error('❌ WASM module failed to initialize:', e);
        throw new Error('WASM module not ready');
      }
    }
    if (!module || !module.ccall) {
      console.error('❌ WASM module still not ready after waiting');
      throw new Error('WASM module not ready');
    }

    // Check for all required WASM functions
    const requiredFunctions = ['_malloc', '_free', 'HEAPU8'];
    for (const func of requiredFunctions) {
      if (!module[func]) {
        console.error(`❌ WASM function ${func} not available`);
        throw new Error(`WASM function ${func} not available`);
      }
    }

    setState(prev => ({
      ...prev,
      status: 'validating',
      progress: 0,
      result: null,
      report: null,
    }));

    try {
      // Reset WASM module before validation
      module.ccall('oms_reset', 'void', [], []);

      const videoBuffer = await file.arrayBuffer();
      const pemBuffer = pemFile ? await pemFile.arrayBuffer() : null;
      
      return new Promise<void>((resolve, reject) => {
        const mp4boxfile = MP4Box.createFile();
        const totalBytes = videoBuffer.byteLength;
        const totalPemBytes = pemBuffer ? pemBuffer.byteLength : 0;
        
        // Match vanilla scope - declare these at function level like vanilla
        let validatedCount = 0;
        let totalProcessedBytes = 0;
        let validationFinished = false;
        let codecType = 0; // Default to H.264
        let codecName = 'H.264';
        const unitTypeCounts: Record<number, number> = {}; // Missing from my implementation!
        
        // 📊 LOGGING: Track different unit sources for debugging
        let sampleNaluCount = 0;
        let processedSpsCount = 0;
        let processedPpsCount = 0;

        let durationInSeconds = 0;

        const createValidationSession = (): boolean => {
          // Check for empty or invalid units
          
          // Allocate WASM memory for the unit data
          const result = module.ccall('oms_init_validation', 'number', ['number'], [codecType]);
          if (result === 1 && totalPemBytes > 0) {
            const pemPtr = module._malloc(totalPemBytes);
            module.HEAPU8.set(new Uint8Array(pemBuffer!), pemPtr);
            const result2 = module.ccall('oms_add_cert', 'number', ['number', 'number'], [pemPtr, totalPemBytes]);
            module._free(pemPtr);
            return result2 === 1;
          } else {
            return result === 1;
          } 
        };

        const validateUnit = (unit: Uint8Array, source: string = 'unknown'): boolean => {
          // Check for empty or invalid units
          if (!unit || unit.length === 0) {
            console.warn(`Empty unit detected from ${source}, skipping`);
            return true; // Skip empty units instead of failing
          }
          
          // Allocate WASM memory for the unit data
          const ptr = module._malloc(unit.length);
          module.HEAPU8.set(unit, ptr);
          const result = module.ccall('oms_validate_nalu', 'number', ['number', 'number', 'number'], [ptr, unit.length, codecType]);
          module._free(ptr);
          
          // Update counters
          validatedCount++;
          totalProcessedBytes += unit.length;

          // Get NALU/OBU type to update counter
          let type: number;
          if (codecType === 0) { // H.264
            // For Annex-B format (with start code), skip the start code
            const dataStart = unit.length >= 4 && unit[0] === 0 && unit[1] === 0 && unit[2] === 0 && unit[3] === 1 ? 4 : 0;
            type = unit[dataStart] & 0x1F;
          } else if (codecType === 1) { // H.265
            const dataStart = unit.length >= 4 && unit[0] === 0 && unit[1] === 0 && unit[2] === 0 && unit[3] === 1 ? 4 : 0;
            type = (unit[dataStart] & 0x7E) >> 1;
          } else { // AV1
            type = (unit[0] & 0x78) >> 3;
          }
          unitTypeCounts[type] = (unitTypeCounts[type] || 0) + 1;
          
          return result === 1;
        };

        const finalizeValidation = () => {
          if (validationFinished) return;
          validationFinished = true;

          // Set progress to 100% like vanilla, then wait a moment before showing results
          setState(prev => ({ ...prev, progress: 100 }));

          // Small delay to ensure progress bar reaches 100% before showing results
          setTimeout(() => {
            const verdict = module.ccall('oms_get_final_verdict', 'number', [], []);
            
            // Log final NALU/OBU summary before showing report
            console.log(`🔢 Added ${validatedCount} units of ${file.name}:`);
            Object.entries(unitTypeCounts).forEach(([type, count]) => {
              console.log(`Type ${type}: ${count} NALUs/OBUs`);
            });

            // Get detailed report
            let reportStr = '';
            try {
              const reportPtr = module.ccall('oms_get_report_str', 'number', ['number'], [durationInSeconds]);
              if (reportPtr) {
                reportStr = module.UTF8ToString(reportPtr);
              }
            } catch (error) {
              console.warn('Failed to get report:', error);
            }

            if (verdict === 1) {
              setState(prev => ({
                ...prev,
                status: 'success',
                result: {
                  codec: codecName,
                  message: 'Video is authentic and the public key is trusted',
                  verdict: 'valid',
                  details: 'The video signature is valid and the content is authentic.',
                  frameCount: validatedCount,
                },
                report: reportStr || null,
              }));
              resolve();
            } else if (verdict === 2) {
              setState(prev => ({
                ...prev,
                status: 'success', // Change to success - not signed is a valid result, not an error
                result: {
                  codec: codecName,
                  message: 'Video is NOT authentic',
                  verdict: 'invalid',
                  details: 'The video is not signed or the signature could not be validated.',
                  frameCount: validatedCount,
                },
                report: reportStr || null,
              }));
              resolve(); // Resolve instead of reject - this is not an error
            } else if (verdict === 3) {
              setState(prev => ({
                ...prev,
                status: 'success', // Change to success - not signed is a valid result, not an error
                result: {
                  codec: codecName,
                  message: 'Video is not signed',
                  verdict: 'unsigned',
                  details: 'The video is not signed or the signature could not be validated.',
                  frameCount: validatedCount,
                },
                report: reportStr || null,
              }));
              resolve(); // Resolve instead of reject - this is not an error
            } else {
              setState(prev => ({
                ...prev,
                status: 'success', // Change to success - not signed is a valid result, not an error
                result: {
                  codec: codecName,
                  message: 'Video authenticity is unknown',
                  verdict: 'unknown',
                  details: 'The video is signed, but no signatures are present.',
                  frameCount: validatedCount,
                },
                report: reportStr || null,
              }));
              resolve(); // Resolve instead of reject - this is not an error
            }
          }, 100); // 100ms delay to let progress bar reach 100%
        };

        mp4boxfile.onError = (e: any) => {
          console.error("MP4Box error:", e);
          setState(prev => ({
            ...prev,
            status: 'error',
            result: {
              codec: 'Unknown',
              message: 'Error parsing video file',
              verdict: 'error',
              details: 'The file could not be parsed as a valid video.',
            },
          }));
          reject(new Error('MP4 parsing error'));
        };

        mp4boxfile.onReady = function (info: any) {
          // Determine file duration
          durationInSeconds = info.duration / info.timescale;
          // Find video track and determine codec
          const videoTrackH264 = info.tracks.find((t: any) => t.codec.startsWith("avc1"));
          const videoTrackH265 = info.tracks.find((t: any) => t.codec.startsWith("hev1"));
          const videoTrackAV1 = info.tracks.find((t: any) => t.codec.startsWith("av01"));
          
          let videoTrack;
          if (videoTrackH264) {
            videoTrack = videoTrackH264;
            codecType = 0;
            codecName = 'H.264';
          } else if (videoTrackH265) {
            videoTrack = videoTrackH265;
            codecType = 1;
            codecName = 'H.265';
          } else if (videoTrackAV1) {
            videoTrack = videoTrackAV1;
            codecType = 2;
            codecName = 'AV1';
          } else {
            setState(prev => ({
              ...prev,
              status: 'error',
              result: {
                codec: 'Unsupported',
                message: 'No supported video codec found',
                verdict: 'error',
                details: 'The video must use H.264, H.265, or AV1 codec.',
              },
            }));
            reject(new Error('Unsupported codec'));
            return;
          }

          // Create media signing session
          if (!createValidationSession()) {
            setState(prev => ({
              ...prev,
              status: 'error',
              result: {
                codec: codecName,
                message: 'Failed to create validation session',
                verdict: 'error',
                details: 'Failed to create validation session.',
                frameCount: validatedCount,
              },
            }));
            validationFinished = true;
            reject(new Error('Failed to create validation session'));
            return;
          }

          // Extract and validate SPS/PPS units for H.264 and H.265
          if (codecType < 2) { // H.264 and H.265 only
            const trackMeta = (mp4boxfile as any).getTrackById(videoTrack.id);
            
            try {
              const entries = trackMeta.mdia.minf.stbl.stsd.entries;
              
              // Validate SPS/PPS units first
              for (const entry of entries) {
                if (entry.avcC) {
                  const spsUnits = entry.avcC.SPS || [];
                  const ppsUnits = entry.avcC.PPS || [];
                  
                  for (const unit of spsUnits.concat(ppsUnits)) {
                    // Handle both data structure formats: unit.data (newer) or unit.nalu (older)
                    const naluData = unit?.data || unit?.nalu;
                    if (!unit || !naluData || !(naluData instanceof Uint8Array)) {
                      console.warn('Skipping invalid SPS/PPS unit', unit);
                      continue;
                    }
                    
                    const nalu = naluData;
                    const naluType = nalu[0] & 0x1F;
                    const unitTypeName = naluType === 7 ? 'SPS' : naluType === 8 ? 'PPS' : `Type${naluType}`;
                    
                    // Create Annex-B format NALU (with start code)
                    const annexBNalu = new Uint8Array(4 + nalu.length);
                    annexBNalu.set([0x00, 0x00, 0x00, 0x01], 0);
                    annexBNalu.set(nalu, 4);

                    if (!validateUnit(annexBNalu, `${unitTypeName}`)) {
                      setState(prev => ({
                        ...prev,
                        status: 'error',
                        result: {
                          codec: codecName,
                          message: 'Failed adding Parameter Sets',
                          verdict: 'error',
                          details: 'Parameter sets could not be added.',
                          frameCount: validatedCount,
                        },
                      }));
                      validationFinished = true;
                      reject(new Error('Failed adding Parameter Sets'));
                      return;
                    }
                    
                    // Count SPS/PPS separately
                    if (naluType === 7) processedSpsCount++;
                    if (naluType === 8) processedPpsCount++;
                  }
                }
              }
              
            } catch (error) {
              console.error('❌ Failed to access track metadata:', error);
            }
          }

          mp4boxfile.setExtractionOptions(videoTrack.id, null, {
            nbSamples: Infinity,
          });
          mp4boxfile.start();
        };

        mp4boxfile.onSamples = function (_id: number, _user: any, samples: any[]) {
          if (validationFinished) return;
          
          // Flatten all NALUs/OBUs from samples
          const allUnits: Uint8Array[] = [];
          for (const sample of samples) {
            if (codecType < 2) {
              // H.264 and H.265 - MP4 replaces the 4 byte start code with the size.
              const nalus = extractNALUsFromLengthPrefixed(new Uint8Array(sample.data));
              allUnits.push(...nalus);
              sampleNaluCount += nalus.length;
            } else {
              // AV1 - Parse the frame into separate OBUs.
              const obus = extractOBUsFromFrame(new Uint8Array(sample.data));
              allUnits.push(...obus);
              sampleNaluCount += obus.length;
            }
          }

          let index = 0;
          const chunkSize = 10; // process 10 Units per batch

          function processChunk() {
            if (validationFinished) return;

            const end = Math.min(index + chunkSize, allUnits.length);
            
            for (; index < end; index++) {
              const unit = allUnits[index];
              if (!validateUnit(unit, `sample-unit-${index + 1}`)) {
                setState(prev => ({
                  ...prev,
                  status: 'error',
                  result: {
                    codec: codecName,
                    message: `Video cannot be validated due to ${codecName === 'AV1' ? 'OBU' : 'NALU'} failure`,
                    verdict: 'error',
                    details: `Validation failed at unit ${index} of ${allUnits.length}`,
                    frameCount: validatedCount,
                  },
                }));
                validationFinished = true;
                reject(new Error(`${codecName === 'AV1' ? 'OBU' : 'NALU'} validation failed`));
                return;
              }
            }
            
            // Update progress bar
            const currentProgress = (totalProcessedBytes / totalBytes) * 100;
            setState(prev => ({ ...prev, progress: currentProgress }));

            if (index < allUnits.length) {
              setTimeout(processChunk, 0);
            } else {
              finalizeValidation();
            }
          }

          processChunk();
        };

        mp4boxfile.onEndOfStream = function () {
          if (validationFinished) return;
          finalizeValidation();
        };

        // Start processing
        const buffer = videoBuffer.slice(0);
        (buffer as any).fileStart = 0;
        mp4boxfile.appendBuffer(buffer);
        mp4boxfile.flush();
      });
    } catch (error) {
      setState(prev => ({
        ...prev,
        status: 'error',
        result: {
          codec: 'Unknown',
          message: 'Validation error',
          verdict: 'error',
          details: error instanceof Error ? error.message : 'Unknown error occurred',
        },
      }));
      throw error;
    }
  }, []);

  return {
    progress: state.progress,
    status: state.status,
    result: state.result,
    report: state.report,
    validateVideo,
    reset,
  };
}
