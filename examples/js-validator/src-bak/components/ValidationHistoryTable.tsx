import React, { useState, useRef } from 'react';
import { makeStyles, tokens } from '@fluentui/react-components';
import ChevronDownIconSvg from '../assets/Chevron.svg';
import DownloadIconSvg from '../assets/ArrowDownload.svg';

export interface ValidationHistoryItem {
  id: string;
  fileName: string;
  fileSize: number;
  timestamp: Date;
  result: any;
  report?: string;
  version?: string;
  status: 'success' | 'error';
}

interface ValidationHistoryTableProps {
  history: ValidationHistoryItem[];
}

const useStyles = makeStyles({
  smv_validationHistoryContainer: {
    backgroundColor: tokens.colorNeutralBackground1,
    overflow: 'hidden',
    fontFamily: '"Open Sans", sans-serif',
  },
  smv_validationHistoryHeader: {
    display: 'flex',
    flexDirection: 'row',
    justifyContent: 'start',
    alignItems: 'center',
    alignSelf: 'stretch',
    gap: tokens.spacingHorizontalXS,
    padding: `${tokens.spacingVerticalSNudge} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalSNudge} ${tokens.spacingHorizontalL}`,
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    fontSize: '18px',
    fontWeight: tokens.fontWeightSemibold,
    lineHeight: tokens.lineHeightBase400,
  },
  smv_countBadge: {
    padding: `${tokens.spacingVerticalNone} ${tokens.spacingHorizontalSNudge} ${tokens.spacingVerticalXXS} ${tokens.spacingHorizontalSNudge}`,
    borderRadius: tokens.borderRadiusCircular,
    backgroundColor: tokens.colorNeutralBackground4,
    fontSize: tokens.fontSizeBase200,
    fontWeight: '700',
    lineHeight: '18px',
    color: tokens.colorNeutralForeground1,
  },
  smv_table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  smv_tableHeader: {
    backgroundColor: tokens.colorNeutralBackground1,
    fontWeight: '600',
    color: tokens.colorNeutralForeground4,
    fontSize: tokens.fontSizeBase300,
    lineHeight: tokens.lineHeightBase300,
    textTransform: 'uppercase',
    letterSpacing: '1px',
    textAlign: 'left',
  },
  smv_tableRowBorderBottom: {
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  },
  smv_tableHeaderCellFileName: {
    padding: `${tokens.spacingVerticalXXL} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalL}`,
    whiteSpace: 'nowrap',
    flex: '1 1 0',
  },
  smv_tableHeaderCellSize: {
    padding: `${tokens.spacingVerticalXXL} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    minWidth: '80px',
    width: '80px',
    whiteSpace: 'nowrap',
  },
  smv_tableHeaderCellDate: {
    padding: `${tokens.spacingVerticalXXL} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    minWidth: '140px',
    width: '140px',
    whiteSpace: 'nowrap',
  },
  smv_tableHeaderCellResult: {
    padding: `${tokens.spacingVerticalXXL} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    minWidth: '100px',
    width: '100px',
    whiteSpace: 'nowrap',
  },
  smv_tableHeaderCellExpand: {
    padding: `${tokens.spacingVerticalXXL} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    minWidth: '40px',
    width: '40px',
    whiteSpace: 'nowrap',
  },
  smv_tableRow: {
    cursor: 'pointer',
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightRegular,
    lineHeight: tokens.lineHeightBase300,
    fontFamily: '"Open Sans", sans-serif',
    color: tokens.colorNeutralForeground1,
  },
  smv_tableRowOdd: {
    backgroundColor: tokens.colorNeutralBackground3,
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground3Hover,
    },
  },
  smv_tableRowEven: {
    backgroundColor: tokens.colorNeutralBackground1,
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground3Hover,
    },
  },
  smv_tableCellFileName: {
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalL}`,
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    lineHeight: '24px',
    verticalAlign: 'middle',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    flex: '1 1 0',
  },
  smv_tableCellSize: {
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    verticalAlign: 'middle',
    whiteSpace: 'nowrap',
  },
  smv_tableCellDate: {
    verticalAlign: 'middle',
    whiteSpace: 'nowrap',
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
  },
  smv_tableCellResult: {
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    verticalAlign: 'middle',
    whiteSpace: 'nowrap',
  },
  smv_resultBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: `${tokens.spacingVerticalXS} ${tokens.spacingHorizontalS}`,
    borderRadius: tokens.borderRadiusCircular,
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightSemibold,
    lineHeight: tokens.lineHeightBase200,
  },
  smv_resultBadgeValid: {
    backgroundColor: '#F4F9EC',
    border: `1px solid #668D2D`,
    color: '#668D2D',
  },
  smv_resultBadgeInvalid: {
    backgroundColor: '#FFF4E5',
    border: `1px solid #B5121B`,
    color: '#B5121B',
  },
  smv_resultBadgeError: {
    backgroundColor: '#FFF5F7',
    border: `1px solid #D67E00`,
    color: '#D67E00',
  },
  smv_tableCellExpand: {
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL} ${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
    textAlign: 'center',
    verticalAlign: 'middle',
    whiteSpace: 'nowrap',
  },
  smv_chevronIcon: {
    width: '24px',
    height: '24px',
    transition: 'transform 0.2s ease',
  },
  smv_chevronIconExpanded: {
    transform: 'rotate(180deg)',
  },
  smv_expandedContent: {
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  },
  smv_reportRowOdd: {
    backgroundColor: tokens.colorNeutralBackground3,
  },
  smv_reportRowEven: {
    backgroundColor: tokens.colorNeutralBackground1,
  },
  smv_expandedContentInner: {
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL}`,
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
  },
  smv_reportContent: {
    fontFamily: 'Monaco, Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase300,
    whiteSpace: 'pre-wrap',
    color: tokens.colorNeutralForeground1,
    overflow: 'auto',
  },
  smv_historyDownloadButtonSection: {
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalNone}`,
  },
  smv_historyDownloadButton: {
    backgroundColor: tokens.colorNeutralForeground1,
    border: 'none',
    cursor: 'pointer',
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    verticalAlign: 'middle',
    justifyContent: 'center',
    borderRadius: tokens.borderRadiusCircular,
    overflow: 'hidden',
    padding: `${tokens.spacingVerticalMNudge} ${tokens.spacingHorizontalM}`,
    gap: tokens.spacingHorizontalXXS,
  },
  smv_historyDownloadIcon: {
    padding: `${tokens.spacingVerticalNone} ${tokens.spacingHorizontalNone}`,
  },
  smv_historyDownloadButtonText: {
    color: tokens.colorNeutralBackground1,
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightSemibold,
    lineHeight: tokens.lineHeightBase300,
    fontFamily: '"Open Sans", sans-serif',
    verticalAlign: 'middle',
  },
});

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function formatDate(date: Date): string {
  return date.toLocaleString('en-GB', {
    hour12: false,
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function getResultStatus(item: ValidationHistoryItem): { label: string; type: 'valid' | 'invalid' | 'unsigned' | 'unkown' | 'error' } {
  if (item.status === 'error') {
    return { label: 'Error', type: 'error' };
  }

  const verdict = item.result?.verdict?.toLowerCase() || '';
  if (verdict === 'valid') return { label: 'Valid', type: 'valid' };
  if (verdict === 'invalid') return { label: 'Not valid', type: 'invalid' };
  if (verdict === 'unsigned') return { label: 'Not signed', type: 'unsigned' };
  if (verdict === 'unknown') return { label: 'Unknown', type: 'unkown' };
  return { label: 'Unknown', type: 'error' };
}

export default function ValidationHistoryTable({ history }: ValidationHistoryTableProps) {
  const styles = useStyles();
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const historyDetailedReportRef = useRef<HTMLDivElement>(null);

  const toggleRow = (id: string) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const historyHandleDownload = (fakeName: string): void => {
    const text = historyDetailedReportRef.current?.innerText;
    
    if (!text) return;

    const blob = new Blob([text], { type: 'text/plain'});
    const url = window.URL.createObjectURL(blob);
    const filenameParts = fakeName.split('.');
    const filenameExtension = filenameParts.pop();
    const downloadExtension = "validation_result.txt";
    const filenameBase = filenameParts.join('.');
    const downloadFilename = filenameExtension === 'mp4' ? `${filenameBase}_${downloadExtension}` : downloadExtension;

    const a = document.createElement('a');
    a.href = url;
    a.download = downloadFilename; // Namnet på filen
    
    document.body.appendChild(a);
    a.click();

    // Cleanup
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  if (history.length === 0) {
    return null;
  }

  return (
    <div className={styles.smv_validationHistoryContainer}>
      {/* Header */}
      <div className={styles.smv_validationHistoryHeader}>
        <span>Validation history</span>
        <span className={styles.smv_countBadge}>{history.length}</span>
      </div>

      {/* Table */}
      <table className={styles.smv_table}>
        <thead className={styles.smv_tableHeader}>
          <tr className={styles.smv_tableRowBorderBottom}>
            <th className={styles.smv_tableHeaderCellFileName}>File name</th>
            <th className={styles.smv_tableHeaderCellSize}>File size</th>
            <th className={styles.smv_tableHeaderCellDate}>Validated at</th>
            <th className={styles.smv_tableHeaderCellResult}>Result</th>
            <th className={styles.smv_tableHeaderCellExpand}></th>
          </tr>
        </thead>
        <tbody>
          {history.map((item, index) => {
            const isExpanded = expandedRows.has(item.id);
            const resultStatus = getResultStatus(item);
            const isEvenRow = index % 2 === 0;

            return (
              <React.Fragment key={item.id}>
                {/* Main Row */}
                <tr 
                  className={`${styles.smv_tableRow} ${isEvenRow ? styles.smv_tableRowOdd : styles.smv_tableRowEven} ${isExpanded ? '' : styles.smv_tableRowBorderBottom}`}
                  onClick={() => toggleRow(item.id)}
                >
                  <td className={styles.smv_tableCellFileName}>{item.fileName}</td>
                  <td className={styles.smv_tableCellSize}>{formatFileSize(item.fileSize)}</td>
                  <td className={styles.smv_tableCellDate}>{formatDate(item.timestamp)}</td>
                  <td className={styles.smv_tableCellResult}>
                    <span className={`${styles.smv_resultBadge} ${
                      resultStatus.type === 'valid' ? styles.smv_resultBadgeValid :
                      resultStatus.type === 'invalid' ? styles.smv_resultBadgeInvalid :
                      styles.smv_resultBadgeError
                    }`}>
                      {resultStatus.label}
                    </span>
                  </td>
                  <td className={styles.smv_tableCellExpand}>
                    <img 
                      src={ChevronDownIconSvg} 
                      alt="Expand" 
                      className={`${styles.smv_chevronIcon} ${isExpanded ? styles.smv_chevronIconExpanded : ''}`}
                    />
                  </td>
                </tr>

                {/* Expanded Content */}
                {isExpanded && (
                  <tr className={`${styles.smv_expandedContent} ${isEvenRow ? styles.smv_reportRowOdd : styles.smv_reportRowEven}`}>
                    <td colSpan={5}>
                      <div className={styles.smv_expandedContentInner}>
                        {/* Detailed Report Section */}
                        {item.report && (
                          <>
                            <div ref={historyDetailedReportRef} className={styles.smv_reportContent}>
                              <div>
                                {item.report}
                                {item.version}
                              </div>
                            </div>
                            <div className={styles.smv_historyDownloadButtonSection}>
                              <button
                                onClick={() => historyHandleDownload(item.fileName)}
                                className={styles.smv_historyDownloadButton}
                              >
                                <img
                                  src={DownloadIconSvg}
                                  alt="Download"
                                  width={20}
                                  height={20}
                                  className={styles.smv_historyDownloadIcon}
                                />
                                <span className={styles.smv_historyDownloadButtonText}>
                                  Download report
                                </span>
                              </button>
                            </div>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
