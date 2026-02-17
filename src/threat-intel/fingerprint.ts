import * as crypto from 'node:crypto';
import type { ThreatFingerprint } from './types.js';
import type { EventScanResult } from '../security/types.js';

/**
 * Generates privacy-safe fingerprints for calendar event content.
 *
 * Two hash types enable different matching strategies:
 * - **Content hash**: SHA-256 of normalized text → catches exact duplicates
 * - **Structural hash**: SHA-256 of content "shape" → catches variants of the same attack
 *
 * Neither hash is reversible back to original content.
 */
export class EventFingerprinter {
  /**
   * Generate a fingerprint from a scan result and the original text content.
   */
  fingerprint(
    scanResult: EventScanResult,
    fieldContents: Record<string, string>,
  ): ThreatFingerprint {
    const combinedText = Object.values(fieldContents).join('\n');
    const contentHash = this.computeContentHash(combinedText);
    const structuralHash = this.computeStructuralHash(combinedText);

    const patternIds = scanResult.fieldResults.flatMap(f =>
      f.detections.map(d => d.ruleId),
    );
    const uniquePatterns = [...new Set(patternIds)];

    const organizerDomain = this.extractDomain(scanResult.organizerEmail);

    return {
      contentHash,
      structuralHash,
      patternIds: uniquePatterns,
      riskScore: scanResult.overallRiskScore,
      organizerDomain,
    };
  }

  /**
   * Content hash: SHA-256 of normalized text.
   * Normalization: lowercase, collapse whitespace, trim.
   * Catches exact duplicate payloads across different events.
   */
  computeContentHash(text: string): string {
    const normalized = text
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();

    return crypto.createHash('sha256').update(normalized, 'utf-8').digest('hex');
  }

  /**
   * Structural hash: SHA-256 of the content "shape".
   * Captures structural features without the actual text, so
   * variants of the same attack (different URLs, names) match.
   *
   * Shape features:
   *   len — text length bucket (0-100, 100-500, 500-2000, 2000-10000, 10000+)
   *   b64 — count of base64-like blocks (32+ chars)
   *   html — sorted list of HTML tag names found
   *   zwc — count of zero-width characters
   *   urls — count of URLs
   *   lines — line count
   *   encoding — count of percent-encoded sequences
   *   scripts — count of script-like patterns (javascript:, data:, etc.)
   */
  computeStructuralHash(text: string): string {
    const shape = this.extractShape(text);
    const shapeString = Object.entries(shape)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}:${v}`)
      .join('|');

    return crypto.createHash('sha256').update(shapeString, 'utf-8').digest('hex');
  }

  /**
   * Extract structural features from text.
   */
  private extractShape(text: string): Record<string, string | number> {
    const len = text.length;
    const lenBucket =
      len < 100 ? '0-100' :
      len < 500 ? '100-500' :
      len < 2000 ? '500-2000' :
      len < 10000 ? '2000-10000' : '10000+';

    // Count base64-like blocks (32+ consecutive base64 chars)
    const b64Matches = text.match(/[A-Za-z0-9+/]{32,}={0,2}/g);
    const b64Count = b64Matches?.length ?? 0;

    // Extract HTML tag names
    const htmlTagMatches = text.match(/<\s*([a-zA-Z][a-zA-Z0-9]*)\b/g);
    const htmlTags = htmlTagMatches
      ? [...new Set(htmlTagMatches.map(t => t.replace(/<\s*/, '').toLowerCase()))].sort()
      : [];

    // Count zero-width characters
    const zwcMatches = text.match(/[\u200B\u200C\u200D\uFEFF\u2060\u180E]/g);
    const zwcCount = zwcMatches?.length ?? 0;

    // Count URLs
    const urlMatches = text.match(/https?:\/\/[^\s)<>"']+/gi);
    const urlCount = urlMatches?.length ?? 0;

    // Line count
    const lineCount = text.split('\n').length;

    // Percent-encoded sequences
    const encodingMatches = text.match(/%[0-9A-Fa-f]{2}/g);
    const encodingCount = encodingMatches?.length ?? 0;

    // Script-like patterns
    let scriptPatterns = 0;
    if (/javascript:/i.test(text)) scriptPatterns++;
    if (/vbscript:/i.test(text)) scriptPatterns++;
    if (/data:\s*[^;]+;\s*base64/i.test(text)) scriptPatterns++;
    if (/<script/i.test(text)) scriptPatterns++;
    if (/on\w+\s*=/i.test(text)) scriptPatterns++;

    return {
      len: lenBucket,
      b64: b64Count,
      html: htmlTags.join(',') || 'none',
      zwc: zwcCount,
      urls: urlCount,
      lines: lineCount,
      encoding: encodingCount,
      scripts: scriptPatterns,
    };
  }

  private extractDomain(email?: string): string | undefined {
    if (!email) return undefined;
    const parts = email.split('@');
    return parts.length === 2 ? parts[1].toLowerCase() : undefined;
  }
}
