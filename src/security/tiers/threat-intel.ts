import type { DetectionTier } from './base-tier.js';
import type { Detection, ScanContext } from '../types.js';
import { ThreatIntelClient, type ThreatIntelClientConfig } from '../../threat-intel/client.js';
import type { ThreatCheckResult } from '../../threat-intel/types.js';

/**
 * Tier 3: Cloud Threat Intelligence
 *
 * Checks event content fingerprints against a community-fed database
 * of known Indirect Prompt Injection payloads.
 *
 * Privacy: only SHA-256 hashes are sent/checked — never raw content.
 *
 * Graceful degradation: if the cloud service is unavailable,
 * this tier returns no detections (zero impact on scanning).
 */
export class ThreatIntelTier implements DetectionTier {
  readonly tierName = 'threat-intel';
  private client: ThreatIntelClient;

  constructor(config?: Partial<ThreatIntelClientConfig>) {
    this.client = new ThreatIntelClient(config);
  }

  /**
   * Analyze text by fingerprinting and checking against known threats.
   *
   * Note: This tier operates on the full text of each field.
   * The fingerprint is computed per-field, not per-event.
   */
  async analyze(text: string, _context: ScanContext): Promise<Detection[]> {
    if (!text || text.length === 0) return [];

    try {
      const fingerprinter = this.client.getFingerprinter();
      const contentHash = fingerprinter.computeContentHash(text);
      const structuralHash = fingerprinter.computeStructuralHash(text);

      // Check both hashes
      const result = await this.client.check({
        contentHash,
        structuralHash,
        patternIds: [],
        riskScore: 0,
      });

      if (!result.known) return [];

      return [this.createDetection(result, contentHash)];
    } catch {
      // Graceful degradation — cloud unavailable
      return [];
    }
  }

  /** Get the underlying client (for reporting, feed sync, etc.). */
  getClient(): ThreatIntelClient {
    return this.client;
  }

  private createDetection(
    result: ThreatCheckResult,
    hash: string,
  ): Detection {
    // Severity scales with cloud confidence and report count
    const baseSeverity = result.confidence;
    const reportBonus = Math.min(result.reportCount * 0.02, 0.15);
    const severity = Math.min(baseSeverity + reportBonus, 1.0);

    return {
      tier: 'threat-intel',
      ruleId: 'THREAT-001',
      ruleName: 'Known Threat Hash',
      severity,
      matchedContent: `Hash ${hash.slice(0, 16)}... matched known threat`,
      matchOffset: 0,
      matchLength: 0,
      confidence: result.confidence,
      metadata: {
        reportCount: result.reportCount,
        firstSeen: result.firstSeen,
        lastSeen: result.lastSeen,
        category: result.category,
      },
    };
  }
}
