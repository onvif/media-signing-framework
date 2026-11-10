import React, { useState, useEffect, useRef } from 'react';
import {
  Text,
  ProgressBar,
} from '@fluentui/react-components';
import { useVideoValidation } from './hooks/useVideoValidation';
import { useVideoValidatorStyles } from './styles/VideoValidator.styles';

// Import SVG icons
import FileIconSvg from './assets/file-icon.svg';
import TrashIconSvg from './assets/Delete.svg';
import ChevronDownIconSvg from './assets/Chevron.svg';
import PlayIconSvg from './assets/PlayIcon.svg';
import PlayIconMiniSvg from './assets/PlayIcon2.svg';
import PauseIconSvg from './assets/pause.svg';
import InfoIconSvg from './assets/info-icon.svg';
import NoteIconSvg from './assets/note-icon.svg';
import ReportIconSvg from './assets/Clipboard.svg';
import DownloadIconSvg from './assets/ArrowDownload.svg';

// Import components
import ValidationHistoryTable from './components/ValidationHistoryTable';
import { ValidationHistoryItem } from './components/ValidationHistoryTable';

type ResultCategory = 'ok' | 'not_ok' | 'unsigned' | 'error' | 'validating' | 'unknown';

// ALWAYS UPDATE THE VERSION IF THE CODE IS TOUCHED/CHANGED!
// There should be a corresponding tag in the repository as well.
const videoValidatorVersion = 'v0.1.0';
const videoValidatorVersionText = `\nTOOL VERSION\n------------\n${videoValidatorVersion}`;

// Helper to parse timestamps from mini report
function parseMiniReportTimestamps(report: string): { start: number; end: number } | null {
  const firstMatch = report.match(/First frame:\s*(.+)/);
  const lastMatch = report.match(/Last validated frame:\s*(.+)/);
  if (!firstMatch || !lastMatch) return null;
  const firstDate = Date.parse(firstMatch[1] + ' UTC');
  const lastDate = Date.parse(lastMatch[1] + ' UTC');
  if (isNaN(firstDate) || isNaN(lastDate)) return null;
  return { start: firstDate / 1000, end: lastDate / 1000 };
}

// Helper to parse verdict from mini report
function parseMiniReportVerdict(report: string): ResultCategory {
  const verdictMatch = report.match(/Verdict:\s*(.+)/);
  if (!verdictMatch) return 'error';
  const verdict = verdictMatch[1].trim().toLowerCase();
  if (verdict === 'valid') return 'ok';
  if (verdict === 'valid, with missing info') return 'ok';
  if (verdict === 'invalid') return 'not_ok';
  if (verdict === 'unsigned') return 'unsigned';
  if (verdict === 'unknown') return 'unknown';
  return 'unknown';
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

export default function VideoValidator() {
  const styles = useVideoValidatorStyles();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [validationHistory, setValidationHistory] = useState<ValidationHistoryItem[]>([]);
  const [pemFiles, setPemFiles] = useState<File[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isPemDragOver, setIsPemDragOver] = useState(false);
  const [lastValidatedFile, setLastValidatedFile] = useState<string | null>(null);
  const [videoUrl, setVideoUrl] = useState<string | null>(null);
  const [VideoAndReport, setVideoAndReport] = useState<{ video: boolean; details: boolean }>({ video: false, details: false });
  const videoRef = useRef<HTMLVideoElement>(null);
  const [isPlayingValidated, setIsPlayingValidated] = useState(false);
  const [reachedSegmentEnd, setReachedSegmentEnd] = useState(false);
  // Validated segment in seconds
  const [validatedRange, setValidatedRange] = useState<{ start: number; end: number } | null>(null);
  const timeUpdateHandlerRef = useRef<((this: HTMLVideoElement, ev: Event) => any) | null>(null);
  const detailedReportRef = useRef<HTMLDivElement>(null);
  // Use the real validation hook
  const { 
    progress,
    status,
    result,
    report,
    validateVideo,
    reset
  } = useVideoValidation();

  // Monitor validation completion and save to history
  useEffect(() => {
    if ((status === 'success' || status === 'error') && selectedFile) {
      
      const historyItem: ValidationHistoryItem = {
        id: Date.now().toString(),
        fileName: selectedFile.name,
        fileSize: selectedFile.size,
        timestamp: new Date(),
        result: result || { message: status === 'error' ? 'Validation failed' : 'Unknown result' },
        report: report || undefined,
        version: videoValidatorVersionText,
        status: status
      };
      
      if (lastValidatedFile === selectedFile.name) {
        // Pop the last item if it's the same file to avoid duplicates
        setValidationHistory(prev => [historyItem, ...prev.slice(1)]);
      } else {
        setValidationHistory(prev => [historyItem, ...prev]);
      }
      setLastValidatedFile(selectedFile.name);
    }
  }, [status, result, report, selectedFile, lastValidatedFile]);

  // Cleanup effect
  useEffect(() => {
    return () => {
      if (videoUrl) URL.revokeObjectURL(videoUrl);
    };
  }, [videoUrl]);

  // Use mini report for validatedRange
  useEffect(() => {
    if (status === 'success') {
      const miniReportPtr = window.Module.ccall('oms_get_mini_report_str', 'number', [], []);
      const miniReportStr = miniReportPtr ? window.Module.UTF8ToString(miniReportPtr) : '';
      const range = parseMiniReportTimestamps(miniReportStr);
      setValidatedRange(range); // Always set, even if null - fixes review comment #1
    }
    if (status === 'error') {
      setValidatedRange(null);
    }
  }, [status]);

  const resetStates = () => {
    setValidatedRange(null);
    setVideoAndReport({ video: false, details: false });
    setIsPlayingValidated(false);
    setReachedSegmentEnd(false);
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Cleanup previous video + listeners
    if (timeUpdateHandlerRef.current && videoRef.current) {
      videoRef.current.removeEventListener('timeupdate', timeUpdateHandlerRef.current);
      timeUpdateHandlerRef.current = null;
    }
    if (videoRef.current) {
      try { videoRef.current.pause(); } catch {}
    }
    if (videoUrl) URL.revokeObjectURL(videoUrl);

    // New file
    setSelectedFile(file);
    setVideoUrl(URL.createObjectURL(file));

    // Reset state for the new file
    resetStates();
    reset();
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
  };

  const handleDragEnter = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    console.log('TESTSTTTSTS -18-');
    event.preventDefault();
    event.stopPropagation();
    setIsDragOver(false);

    const file = event.dataTransfer.files?.[0];
    const item = event.dataTransfer.items?.[0]?.webkitGetAsEntry();
    if (!file) return;
    console.log('file dropped:', file.name, file.type, file.size, item?.isFile, item?.isDirectory, item?.name);
    if (item && item.isDirectory) { 
      console.log('file is a directory');
    }

    // Check if it's a video file
    if (!file.type.startsWith('video/')) {
      alert('Please drop a video file (MP4)');
      return;
    }

    // Cleanup previous video + listeners
    if (timeUpdateHandlerRef.current && videoRef.current) {
      videoRef.current.removeEventListener('timeupdate', timeUpdateHandlerRef.current);
      timeUpdateHandlerRef.current = null;
    }
    if (videoRef.current) {
      try { videoRef.current.pause(); } catch {}
    }
    if (videoUrl) URL.revokeObjectURL(videoUrl);

    // New file
    setSelectedFile(file);
    setVideoUrl(URL.createObjectURL(file));

    // Reset state for the new file
    resetStates();
    reset();
  };

  const handlePemFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Add file
    setPemFiles(prev => [...prev, file]);
  };

  const handlePemDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
  };

  const handlePemDragEnter = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setIsPemDragOver(true);
  };

  const handlePemDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setIsPemDragOver(false);
  };

  const handlePemDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setIsPemDragOver(false);

    const file = event.dataTransfer.files?.[0];
    if (!file) return;

    // Check if it's a PEM file
    // if (!file.type.startsWith('application/x-pem-file')) {
    if (!file.type.startsWith('application/')) {
      alert('Please drop a PEM file');
      return;
    }

    // Add file
    setPemFiles(prev => [...prev, file]);
  };

  const displayPem = async (pem: File) => {
    if (!pem) return;

    // // Typ-annoteringar (: HTMLDialogElement etc.) behövs bara i TypeScript
    // const dialog = document.getElementById('myPopup') as HTMLDialogElement;
    // const closeBtn = document.getElementById('closeBtn') as HTMLButtonElement;

    // // Visa popupen centrerat på skärmen
    // openBtn.addEventListener('click', () => {
    //   dialog.showModal(); 
    // });

    // // Stäng popupen
    // closeBtn.addEventListener('click', () => {
    //   dialog.close();
    // });
    const buffer = await pem.arrayBuffer();
    try {
      if (!window.Module || !window.Module.ccall) {
        console.error('❌ WASM module not ready');
        alert('WASM module not ready yet. Please refresh and try again.');
        return;
      }
      // Use OpenSSL via WASM to print certificate details
      const pemPtr = window.Module._malloc(buffer.byteLength);
      window.Module.HEAPU8.set(new Uint8Array(buffer), pemPtr);
      const resultPtr = window.Module.ccall('oms_print_cert', 'number', ['number', 'number'], [pemPtr, buffer.byteLength]);
      window.Module._free(pemPtr);
      if (resultPtr) {
        const certText = window.Module.UTF8ToString(resultPtr);
        // dialog.showModal(); 
        alert(`Certificate "${pem.name}":\n${certText}`);
      }
    } catch (error) {
      console.warn(`Failed to print certificate "${pem.name}":`, error);
    }
  };

  const handleValidate = async () => {
    if (!selectedFile) return;
    
    try {
      if (!window.Module || !window.Module.ccall) {
        console.error('❌ WASM module not ready');
        alert('WASM module not ready yet. Please refresh and try again.');
        return;
      }
      
      await validateVideo(selectedFile, pemFiles);
    } catch (error) {
      console.error('❌ Validation error:', error);
      alert('Validation failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  const handleDownload = (): void => {
    console.log('TESTSTTTSTS -19-');
    const text = detailedReportRef.current?.innerText;

    if (!selectedFile) return;
    if (!text) return;

    const blob = new Blob([text], { type: 'text/plain'});
    const url = window.URL.createObjectURL(blob);
    const filenameParts = selectedFile.name.split('.');
    const filenameExtension = filenameParts.pop();
    const downloadExtension = "validation_result.txt";
    const filenameBase = filenameParts.join('.');
    const downloadFilename = filenameExtension === 'mp4' ? `${filenameBase}_${downloadExtension}` : downloadExtension;

    const a = document.createElement('a');
    a.href = url;
    a.download = downloadFilename;

    document.body.appendChild(a);
    a.click();

    // Cleanup
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const playValidatedSegment = async () => {
    console.log('TESTSTTTSTS -20-');
    const el = videoRef.current;
    const range = validatedRange;
    if (!el) {
      console.warn('[segment] no video element');
      return;
    }
    if (!range || !(range.end > range.start)) {
      console.warn('[segment] invalid range', range);
      return;
    }

    // Map absolute timestamps to video timeline offsets
    // The video timeline starts at validatedRange.start
    const segmentStart = 0;
    const segmentEnd = range.end - range.start;

    // Wait until we can seek
    const waitForMetadata = () =>
      new Promise<void>((resolve) => {
        if (el.readyState >= 1 && el.duration && !Number.isNaN(el.duration)) return resolve(); // HAVE_METADATA
        const onLoaded = () => {
          el.removeEventListener('loadedmetadata', onLoaded);
          resolve();
        };
        el.addEventListener('loadedmetadata', onLoaded, { once: true });
      });

    const waitForSeekable = () =>
      new Promise<void>((resolve) => {
        const hasSeekable = () => el.seekable && el.seekable.length > 0;
        if (hasSeekable()) return resolve();
        const onCanPlay = () => {
          if (hasSeekable()) {
            el.removeEventListener('canplay', onCanPlay);
            resolve();
          }
        };
        el.addEventListener('canplay', onCanPlay);
      });

    await waitForMetadata().catch(() => {});
    await waitForSeekable().catch(() => {});

    // Clamp end to duration
    const end = Math.min(segmentEnd, Number.isFinite(el.duration) ? el.duration : segmentEnd);
    const start = Math.max(0, Math.min(segmentStart, end - 0.001));

    // Remove previous timeupdate handler if any
    if (timeUpdateHandlerRef.current) {
      el.removeEventListener('timeupdate', timeUpdateHandlerRef.current);
      timeUpdateHandlerRef.current = null;
    }

    // Handler that pauses at `end`
    const onTimeUpdate = () => {
      if (el.currentTime >= end) {
        el.pause();
        setReachedSegmentEnd(true);
        setIsPlayingValidated(false);
        if (timeUpdateHandlerRef.current) {
          el.removeEventListener('timeupdate', timeUpdateHandlerRef.current);
          timeUpdateHandlerRef.current = null;
        }
        // Snap exactly to end (optional)
        try { el.currentTime = end; } catch {}
      }
    };
    timeUpdateHandlerRef.current = onTimeUpdate;
    el.addEventListener('timeupdate', onTimeUpdate);

    // Seek then play
    try { el.pause(); } catch {}
    try { el.currentTime = start; } catch (e) {
      console.warn('[segment] failed to seek', e);
    }

    try {
      const p = el.play();
      if (p && typeof p.then === 'function') {
        await p.catch(err => {
          console.warn('[segment] play blocked or failed', err);
        });
      }
    } catch (err) {
      console.warn('[segment] play threw', err);
    }
  };

  // Use mini report for result classification
  const classifyResult = (): ResultCategory => {
    console.log('TESTSTTTSTS -21-');
    if (status === 'validating') return 'validating';
    if (status === 'error') return 'error';

    if (status === 'success') {
      const miniReportPtr = window.Module.ccall('oms_get_mini_report_str', 'number', [], []);
      const miniReportStr = miniReportPtr ? window.Module.UTF8ToString(miniReportPtr) : '';
      return parseMiniReportVerdict(miniReportStr);
    }

    return 'unknown';
  };

  return (
    <>
      <div className={styles.smv_container}>
        {/* Validator Area */}
        <div className={styles.smv_validatorArea}>
          {/* Validator Area Container */}
          <div className={styles.smv_validatorAreaContainer}>
            {/* Upload Area - Always visible */}
            <div className={styles.smv_CAContainer}>
              <div
                // className={styles.smv_uploadAreaContainer}
                className={`${styles.smv_uploadAreaContainer} ${isPemDragOver ? styles.smv_uploadAreaDragOver : ''}`}
                onDragOver={handlePemDragOver}
                onDragEnter={handlePemDragEnter}
                onDragLeave={handlePemDragLeave}
                onDrop={handlePemDrop}
              >
                <span className={styles.smv_uploadAreaText}>Drag and drop a trusted CA file here or</span>
                <div
                  className={styles.smv_browseFileButton}
                  onClick={() => document.getElementById('pemInput')?.click()}
                >
                  <span className={styles.smv_browseFileButtonText}>Browse file</span>
                  <input
                    id="pemInput"
                    type="file"
                    style={{ display: 'none' }}
                    accept="application/x-pem-file"
                    onChange={handlePemFileSelect}
                    className={styles.smv_hiddenInput}
                  />
                </div>
                <span className={styles.smv_uploadHint}>Supports PEM files only. <Text className={styles.smv_uploadHint2}>Only one file at a time</Text>.</span>
              </div>
              <div className={styles.smv_uploadCAContainer}>
                <span className={styles.smv_CAHint}>Uploaded trusted CA certificates</span>
                <table className={styles.smv_CAtable}>
                {/* {pemFiles.map((pem, index) => {
                  return (
                    <React.Fragment key={pem.name}>
                      <span className={styles.smv_uploadHint}>{index + 1}: {pem.name} ({formatFileSize(pem.size)})</span>
                    </React.Fragment>
                  );
                })} */}
                  <thead className={styles.smv_CAtableHeader}>
                    <tr className={styles.smv_CAtableRowBorderBottom}>
                      <th className={styles.smv_CAtableHeaderCellNum}>#</th>
                      <th className={styles.smv_CAtableHeaderCellFileName}>File name</th>
                      <th className={styles.smv_CAtableHeaderCellSize}>File size</th>
                      {/* <th className={styles.smv_tableHeaderCellExpand}></th> */}
                    </tr>
                  </thead>
                  <tbody>
                    {pemFiles.map((pem, index) => {
                      return (
                        <React.Fragment key={pem.name}>
                          {/* Main Row */}
                          <tr 
                            // className={`${styles.smv_CAtableRow} ${styles.smv_CAtableRowEven} ${styles.smv_CAtableRowBorderBottom}`}
                            className={`${styles.smv_CAtableRow} ${styles.smv_CAtableRowEven}`}
                            // id={`openCA${index}`}
                            onClick={() => displayPem(pem)}
                          >
                            <td className={styles.smv_CAtableCellNum}>{index + 1}</td>
                            <td className={styles.smv_CAtableCellFileName}>{pem.name}</td>
                            <td className={styles.smv_CAtableCellSize}>{formatFileSize(pem.size)}</td>
                            {/* <td className={styles.smv_CAtableCellExpand}>
                              <img 
                                src={ChevronDownIconSvg} 
                                alt="Expand" 
                                className={`${styles.smv_chevronIcon} ${isExpanded ? styles.smv_chevronIconExpanded : ''}`}
                              />
                            </td> */}
{/* <dialog id="myPopup">
  <p>Här är din popup-text!</p>
  <button id="closeBtn">Stäng</button>
</dialog>                          </tr> */}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
            <div
              className={`${styles.smv_uploadAreaContainer} ${isDragOver ? styles.smv_uploadAreaDragOver : ''}`}
              onDragOver={handleDragOver}
              onDragEnter={handleDragEnter}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
            >
              <span className={styles.smv_uploadAreaText}>
                {/* {selectedFile ? 'Drag and drop a different video file for verification here or' : 'Drag and drop your video file for verification here or'} */}
                Drag and drop your video file for verification here or
              </span>
              <div
                className={styles.smv_browseFileButton}
                onClick={() => document.getElementById('videoInput')?.click()}
              >
                <span className={styles.smv_browseFileButtonText}>Browse file</span>
                <input
                  id="videoInput"
                  type="file"
                  style={{ display: 'none' }}
                  accept="video/*"
                  onChange={handleFileSelect}
                  className={styles.smv_hiddenInput}
                />
              </div>
              <span className={styles.smv_uploadHint}>Supports MP4 files only. <Text className={styles.smv_uploadHint2}>Only one file at a time</Text>.</span>
            </div>

            {selectedFile && (
              <>
                {/* Combined File Info + Validation Results Container */}
                <div className={styles.smv_fileInfoContainer}>
                  {/* File Info Section */}
                  <div className={styles.smv_fileInfoSection}>
                    {/* File details on the left */}
                    <div className={styles.smv_fileDetailsLeft}>
                      {/* File icon */}
                      <img src={FileIconSvg} alt="File" width={48} height={48} />
                      <div className={styles.smv_fileNameSizeProgressBarText}>
                        <div className={styles.smv_fileNameSizeText}>
                          <div className={styles.smv_fileNameText}>
                            {selectedFile.name}
                          </div>
                          <div className={styles.smv_fileSizeText}>
                            <div>File size: {formatFileSize(selectedFile.size)}</div>
                            {status === 'validating' && (
                              <div>{Math.round(progress)}%</div>
                            )}
                          </div>
                        </div>
                        {status === 'validating' && (
                          <div className={styles.smv_progressSection}>
                            <ProgressBar value={progress / 100} />
                          </div>
                        )}
                      </div>
                    </div>
                    {/* Right side: Delete icon and Validate button (only before/during validation) */}
                    <div className={styles.smv_fileActionsRight}>
                      {/* Delete/trash icon */}
                      <img
                        src={TrashIconSvg}
                        alt="Delete"
                        className={styles.smv_trashIcon}
                        onClick={() => {
                          setSelectedFile(null);
                          reset();
                        }}
                      />
                      {/* Validate Button - only show before validation is complete */}
                      {/* {status !== 'success' && !result && ( */}
                        <button
                          onClick={handleValidate}
                          className={`${styles.smv_validateButton} ${styles.smv_validateButtonEnabled}`}
                        >
                          <span className={styles.smv_validateButtonText}>
                            {/* Validate media */}
                            {/* {status === 'success' && result ? 'Validate media' : 'Re-validate media'} */}
                            {result ? 'Re-validate media' : 'Validate media'}
                          </span>
                        </button>
                      {/* )} */}
                    </div>
                  </div>

                  {/* Horizontal Divider - only show after validation */}
                  {status === 'success' && result && (
                    <div className={styles.smv_horizontalDivider} />
                  )}

                  {/* Validation Results Section - inside the same container */}
                  {status === 'success' && result && (
                    <div className={styles.smv_validationResultsContainer}>
                      <div className={styles.smv_validationResultsSection}>
                        {/* Validation result header with pill badge */}
                        <div className={styles.smv_validationResultHeader}>
                          <Text className={styles.smv_validationResultTitle}>
                            Validation result
                          </Text>
                          {/* Valid/Not Valid/Not signed pill badge */}
                          <div className={classifyResult() === 'ok' ? styles.smv_validBadge : (classifyResult() === 'not_ok' ? styles.smv_notValidBadge : styles.smv_warningBadge)}>
                            <span className={`${styles.smv_badgeText} ${classifyResult() === 'ok' ? styles.smv_validBadgeText : (classifyResult() === 'not_ok' ? styles.smv_notValidBadgeText : (classifyResult() === 'unsigned' ? styles.smv_unsignedBadgeText : styles.smv_warningBadgeText))}`}>
                              {classifyResult() === 'ok' ? 'Valid' : (classifyResult() === 'not_ok' ? 'Not Valid' : (classifyResult() === 'unsigned' ? 'Not signed' : 'Unknown'))}
                            </span>
                          </div>
                        </div>

                        {/* Summary, Player, Report - horizontal layout */}
                        <div className={styles.smv_resultDetailsRow}>
                          <div className={styles.resultDetailsItems}>
                            {/* Summary */}
                            {result.message && (
                              <div className={styles.smv_resultDetailItem}>
                                <Text className={styles.smv_resultDetailText1}>
                                  Summary:
                                </Text>
                                <Text className={styles.smv_resultDetailText2}>
                                  {result.message}
                                </Text>
                              </div>
                            )}
                          </div>

                          {/* Player and Detailed Report Link */}
                          <div className={styles.smv_inlineVideoAndReport}>
                            {/* Detailed Report Link */}
                            {report && (
                              <div 
                                className={styles.smv_inlineReportToggle}
                                onClick={() => {
                                  setIsPlayingValidated(false);
                                  setVideoAndReport({ video: false, details: !(VideoAndReport.details) })}}
                              >
                                <img src={ReportIconSvg} alt="Report" width={24} height={24} />
                                <Text className={styles.smv_inlineReportText}>
                                  {/* Detailed report */}
                                  {VideoAndReport.details ? 'Hide detailed report' : 'Show detailed report'}
                                </Text>
                                <img
                                  src={ChevronDownIconSvg}
                                  alt="Expand"
                                  width={24}
                                  height={24}
                                  className={VideoAndReport.details ? styles.smv_chevronExpanded : ''}
                                />
                              </div>
                            )}
                            {videoUrl && classifyResult() === 'ok' && (
                              <div
                                className={styles.smv_inlineReportToggle}
                                onClick={() => {
                                  setIsPlayingValidated(false);
                                  setVideoAndReport({ video: !(VideoAndReport.video), details: false })}}
                              >
                                <img src={PlayIconSvg} alt="Report" width={24} height={24} />
                                <Text className={styles.smv_inlineReportText}>
                                  {VideoAndReport.video ? 'Hide validated video' : 'Show validated video'}
                                </Text>
                                <img 
                                  src={ChevronDownIconSvg}
                                  alt="Expand"
                                  width={24}
                                  height={24}
                                  className={VideoAndReport.video ? styles.smv_chevronExpanded : ''}
                                />
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Detailed Validation Report Content - shown when expanded */}
                      {report && VideoAndReport.details && (
                        <>
                          <div ref={detailedReportRef} className={styles.smv_reportToFile}>
                            <div className={styles.smv_reportTextContainer}>
                              <div className={styles.smv_reportText}>{report}</div>
                              <div className={styles.smv_reportText}>{videoValidatorVersionText}</div>
                            </div>
                          </div>
                          <div className={styles.smv_downloadButtonSection}>
                            <button
                              onClick={handleDownload}
                              className={styles.smv_downloadButton}
                            >
                              <img
                                src={DownloadIconSvg}
                                alt="Download"
                                width={20}
                                height={20}
                                className={styles.smv_downloadIcon}
                              />
                              <span className={styles.smv_downloadButtonText}>
                                Download report
                              </span>
                            </button>
                          </div>
                        </>
                      )}

                      {/* Validated Video Player - Expandable section inside validation result */}
                      {videoUrl && VideoAndReport.video && (
                        <>
                          <video
                            ref={videoRef}
                            src={videoUrl}
                            controls
                            playsInline
                            className={styles.smv_videoElement}
                          />
                          <div className={styles.smv_videoControlsRow}>
                            <div
                              className={styles.smv_playFileButton}
                              onClick={() => {
                                {isPlayingValidated ? videoRef.current?.pause() : (videoRef.current?.currentTime && videoRef.current?.currentTime > 0  && !reachedSegmentEnd ? videoRef.current?.play() : playValidatedSegment())};
                                setIsPlayingValidated(!isPlayingValidated);
                              }}
                            >
                              <img
                                alt="!"
                                src={isPlayingValidated ? PauseIconSvg : PlayIconMiniSvg}
                                className={styles.smv_playIconMini}
                              />
                              <Text className={styles.smv_noteText}>
                                {isPlayingValidated ? 'Pause validated segment' : 'Play validated segment'}
                              </Text>
                            </div>
                            {validatedRange && (
                              <Text className={styles.smv_validatedRangeText}>
                                <span className={styles.smv_rangeLabelHeader}>Validated range:</span>
                                <span>
                                <Text className={styles.smv_rangeLabel}>Start: </Text>
                                  {new Date(validatedRange.start * 1000).toLocaleString("en-GB", {
                                    hour12: false, year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
                                  })}
                                </span>
                                <span>
                                <Text className={styles.smv_rangeLabel}>End: </Text>
                                  {new Date(validatedRange.end * 1000).toLocaleString("en-GB", {
                                    hour12: false, year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
                                  })}
                                </span>
                              </Text>
                            )}
                          </div>
                          <div className={styles.smv_noteTextContainer}>
                            <div className={styles.smv_noteHeader}>
                              <img
                                alt="!"
                                src={NoteIconSvg}
                                className={styles.smv_noteIcon}
                              />
                              <Text className={styles.smv_noteText}>
                                NOTE
                              </Text>
                            </div>
                            <div>
                              <span className={styles.smv_noteHint}>
                                <Text className={styles.smv_noteHint2}>Playback options</Text><br/>
                                Playing the video using
                                <Text className={styles.smv_noteHint2}> built-in player controls </Text>
                                plays the full original file, including validated and unvalidated segments.<br/>
                                Use the <Text className={styles.smv_noteHint2}>button above</Text> to play
                                only validated segment.<br/><br/>
                                <Text className={styles.smv_noteHint2}>Codec support</Text><br/>
                                Not all browsers have H.265 support for video playback.
                              </span>
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </>
            )}
          </div> {/* Validator Area Container */}

          {/* Privacy Notice */}
          <div className={styles.smv_privacyNotice}>
            <img
              alt="!"
              src={InfoIconSvg}
              className={styles.smv_privacyIcon}
            />
            <div className={styles.smv_privacyText}>
              <div className={styles.smv_privacyHeader}>
                Privacy First
              </div>
              <div className={styles.smv_privacyFooter}>
                All video processing happens locally in your browser. Your files never leave
                your device and are not uploaded to any server.
              </div>
            </div>
          </div>
          {/* Validation History - New Table Component */}
          <ValidationHistoryTable history={validationHistory} />
        </div> {/* Validator Area */}
      </div>
    </>
  );
}

declare global {
  interface Window {
    Module: any;
  }
}
