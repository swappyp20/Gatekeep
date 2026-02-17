import type { FieldScanResult } from '../types.js';
import { SecurityAction } from '../types.js';

/**
 * Redacts dangerous content from calendar event fields,
 * preserving safe content where possible.
 */
export class ContentRedactor {
  /**
   * Apply redaction based on the scan result's action.
   */
  redact(originalContent: string, scanResult: FieldScanResult): string {
    switch (scanResult.action) {
      case SecurityAction.BLOCK:
        return `[GATEKEEP: Content blocked — ${scanResult.detections.length} threat(s) detected. Use gatekeep-view-quarantined to inspect.]`;

      case SecurityAction.REDACT:
        return this.redactDangerousContent(originalContent, scanResult);

      case SecurityAction.FLAG:
      case SecurityAction.PASS:
        return originalContent;
    }
  }

  private redactDangerousContent(
    content: string,
    scanResult: FieldScanResult,
  ): string {
    // Sort detections by offset descending so we can splice without shifting indices
    const sorted = [...scanResult.detections]
      .filter(d => d.matchLength > 0 && d.matchOffset >= 0)
      .sort((a, b) => b.matchOffset - a.matchOffset);

    let result = content;
    for (const det of sorted) {
      const before = result.slice(0, det.matchOffset);
      const after = result.slice(det.matchOffset + det.matchLength);
      result = `${before}[REDACTED:${det.ruleId}]${after}`;
    }

    return result;
  }
}
