import type { Env } from '../index.js';

/** Stored threat entry in KV. */
export interface StoredThreat {
  hash: string;
  hashType: 'content' | 'structural';
  reportCount: number;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  /** Aggregated pattern IDs across all reports. */
  patternIds: string[];
  /** Most recent reporter's organizer domain. */
  organizerDomain?: string;
  /** Threat category (derived from pattern IDs). */
  category?: string;
}

const KV_PREFIX = 'threat:';
const FEED_PREFIX = 'feed:';
const CONFIDENCE_THRESHOLD = 0.60;
const MIN_REPORTS_FOR_FEED = 2;

/**
 * KV-backed storage for threat fingerprints.
 */
export class FingerprintStore {
  private kv: KVNamespace;

  constructor(env: Env) {
    this.kv = env.THREAT_STORE;
  }

  /**
   * Record a threat report. Creates or updates the stored entry.
   * Returns the updated entry.
   */
  async recordReport(
    hash: string,
    patternIds: string[],
    riskScore: number,
    organizerDomain?: string,
  ): Promise<StoredThreat> {
    const key = KV_PREFIX + hash;
    const existing = await this.kv.get<StoredThreat>(key, 'json');

    const now = new Date().toISOString();

    if (existing) {
      // Update existing entry
      const updatedPatterns = [...new Set([...existing.patternIds, ...patternIds])];
      const updated: StoredThreat = {
        ...existing,
        reportCount: existing.reportCount + 1,
        lastSeen: now,
        patternIds: updatedPatterns,
        confidence: this.calculateConfidence(existing.reportCount + 1, riskScore),
        organizerDomain: organizerDomain ?? existing.organizerDomain,
        category: this.deriveCategory(updatedPatterns),
      };

      await this.kv.put(key, JSON.stringify(updated), {
        expirationTtl: 30 * 24 * 60 * 60, // 30 days
      });

      // Add to feed if meets threshold
      if (updated.reportCount >= MIN_REPORTS_FOR_FEED && updated.confidence >= CONFIDENCE_THRESHOLD) {
        await this.addToFeed(updated);
      }

      return updated;
    }

    // Create new entry
    const entry: StoredThreat = {
      hash,
      hashType: 'content', // determined by caller context
      reportCount: 1,
      confidence: this.calculateConfidence(1, riskScore),
      firstSeen: now,
      lastSeen: now,
      patternIds,
      organizerDomain,
      category: this.deriveCategory(patternIds),
    };

    await this.kv.put(key, JSON.stringify(entry), {
      expirationTtl: 30 * 24 * 60 * 60,
    });

    return entry;
  }

  /**
   * Check if a hash is a known threat.
   */
  async check(hash: string): Promise<StoredThreat | null> {
    const key = KV_PREFIX + hash;
    return this.kv.get<StoredThreat>(key, 'json');
  }

  /**
   * Get feed entries since a given timestamp.
   * Returns high-confidence threats added/updated after the timestamp.
   */
  async getFeedSince(since: string | null): Promise<StoredThreat[]> {
    // List all feed entries
    const entries: StoredThreat[] = [];
    let cursor: string | undefined;
    const sinceTime = since ? new Date(since).getTime() : 0;

    do {
      const result = await this.kv.list({
        prefix: FEED_PREFIX,
        cursor,
        limit: 100,
      });

      for (const key of result.keys) {
        const entry = await this.kv.get<StoredThreat>(key.name, 'json');
        if (entry && new Date(entry.lastSeen).getTime() > sinceTime) {
          entries.push(entry);
        }
      }

      cursor = result.list_complete ? undefined : result.cursor;
    } while (cursor);

    return entries;
  }

  private async addToFeed(entry: StoredThreat): Promise<void> {
    const key = FEED_PREFIX + entry.hash;
    await this.kv.put(key, JSON.stringify(entry), {
      expirationTtl: 30 * 24 * 60 * 60,
    });
  }

  /**
   * Calculate confidence based on report count and risk score.
   * More reports = higher confidence. High local risk score = higher base.
   */
  private calculateConfidence(reportCount: number, riskScore: number): number {
    const reportFactor = Math.min(reportCount * 0.1, 0.5);
    const riskFactor = riskScore * 0.5;
    return Math.min(reportFactor + riskFactor, 1.0);
  }

  /**
   * Derive a threat category from pattern IDs.
   */
  private deriveCategory(patternIds: string[]): string {
    const hasStruct = patternIds.some(id => id.startsWith('STRUCT'));
    const hasCtx = patternIds.some(id => id.startsWith('CTX'));

    if (patternIds.some(id => ['CTX-001', 'CTX-005'].includes(id))) return 'prompt-injection';
    if (patternIds.some(id => ['CTX-003', 'CTX-008'].includes(id))) return 'code-execution';
    if (patternIds.some(id => ['CTX-004'].includes(id))) return 'tool-call-injection';
    if (patternIds.some(id => ['CTX-009'].includes(id))) return 'data-exfiltration';
    if (patternIds.some(id => ['STRUCT-003', 'STRUCT-004'].includes(id))) return 'xss-injection';
    if (hasStruct && hasCtx) return 'multi-vector';
    if (hasStruct) return 'structural-attack';
    if (hasCtx) return 'semantic-attack';
    return 'unknown';
  }
}
