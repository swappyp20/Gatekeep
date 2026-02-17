import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { ThreatIntelCache } from './cache.js';
import { EventFingerprinter } from './fingerprint.js';
import type {
  ThreatFingerprint,
  ThreatReport,
  ThreatCheckResult,
  ThreatFeedEntry,
} from './types.js';

export interface ThreatIntelClientConfig {
  /** Cloud API base URL. */
  apiUrl: string;
  /** Whether cloud API calls are enabled. */
  enabled: boolean;
  /** Feed sync interval in minutes. */
  syncIntervalMinutes: number;
  /** Directory for client state (client ID, cache). */
  stateDir?: string;
  /** Cache TTL in hours. */
  cacheTtlHours?: number;
}

const DEFAULT_CONFIG: ThreatIntelClientConfig = {
  apiUrl: 'https://api.calguard.dev/v1',
  enabled: false,
  syncIntervalMinutes: 15,
};

/**
 * Client for the CalGuard Cloud Threat Intelligence service.
 *
 * Privacy-first: only SHA-256 fingerprints are sent to the cloud.
 * Never raw calendar content.
 *
 * Behavior:
 * - **check()**: Local cache first (always fast). Cloud check async if cache miss.
 * - **report()**: Fire-and-forget on DANGEROUS+ detections.
 * - **syncFeed()**: Pull new threat hashes periodically into local cache.
 * - **Graceful degradation**: If cloud is unavailable, returns cache results only.
 */
export class ThreatIntelClient {
  private config: ThreatIntelClientConfig;
  private cache: ThreatIntelCache;
  private fingerprinter: EventFingerprinter;
  private clientId: string | null = null;
  private lastSyncTime: number = 0;
  private stateDir: string;

  constructor(config?: Partial<ThreatIntelClientConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.stateDir = this.config.stateDir ?? path.join(os.homedir(), '.calguard');
    this.cache = new ThreatIntelCache({
      cacheDir: path.join(this.stateDir, 'cache'),
      cacheTtlHours: this.config.cacheTtlHours,
    });
    this.fingerprinter = new EventFingerprinter();
  }

  /** Get the fingerprinter for external use (e.g., ThreatIntelTier). */
  getFingerprinter(): EventFingerprinter {
    return this.fingerprinter;
  }

  /**
   * Check if a content hash or structural hash is a known threat.
   * Always checks local cache first. If cloud is enabled and cache misses,
   * performs async cloud lookup and caches the result.
   */
  async check(fingerprint: ThreatFingerprint): Promise<ThreatCheckResult> {
    // Check local cache for both hashes
    const cachedContent = await this.cache.get(fingerprint.contentHash);
    if (cachedContent?.known) return cachedContent;

    const cachedStructural = await this.cache.get(fingerprint.structuralHash);
    if (cachedStructural?.known) return cachedStructural;

    // If cloud is disabled, return negative result
    if (!this.config.enabled) {
      return { known: false, confidence: 0, reportCount: 0 };
    }

    // Cloud check (non-blocking — we cache the result for next time)
    try {
      const cloudResult = await this.cloudCheck(fingerprint.contentHash);
      await this.cache.set(fingerprint.contentHash, cloudResult);

      if (cloudResult.known) return cloudResult;

      // Also check structural hash
      const structuralResult = await this.cloudCheck(fingerprint.structuralHash);
      await this.cache.set(fingerprint.structuralHash, structuralResult);

      if (structuralResult.known) return structuralResult;
    } catch {
      // Cloud unavailable — return negative
    }

    return { known: false, confidence: 0, reportCount: 0 };
  }

  /**
   * Report a threat fingerprint to the cloud service.
   * Fire-and-forget — errors are silently swallowed.
   * Only call for DANGEROUS+ detections.
   */
  async report(fingerprint: ThreatFingerprint): Promise<void> {
    if (!this.config.enabled) return;

    try {
      const clientId = await this.getClientId();

      const report: ThreatReport = {
        clientId,
        fingerprint,
        reportedAt: new Date().toISOString(),
      };

      await this.cloudReport(report);
    } catch {
      // Silent failure — reporting is supplementary
    }
  }

  /**
   * Sync the threat feed from the cloud service.
   * Pulls new high-confidence threat hashes since the last sync.
   * Results are imported into the local cache.
   */
  async syncFeed(): Promise<number> {
    if (!this.config.enabled) return 0;

    const now = Date.now();
    const syncIntervalMs = this.config.syncIntervalMinutes * 60 * 1000;

    // Skip if synced recently
    if (now - this.lastSyncTime < syncIntervalMs) return 0;

    try {
      const since = this.lastSyncTime > 0
        ? new Date(this.lastSyncTime).toISOString()
        : new Date(now - 24 * 60 * 60 * 1000).toISOString(); // last 24h on first sync

      const entries = await this.cloudFeed(since);
      const imported = await this.cache.importFeed(entries);
      this.lastSyncTime = now;
      return imported;
    } catch {
      return 0;
    }
  }

  /**
   * Get the anonymous client ID (generated on first run).
   */
  async getClientId(): Promise<string> {
    if (this.clientId) return this.clientId;

    const idFile = path.join(this.stateDir, 'client-id');

    try {
      this.clientId = (await fs.promises.readFile(idFile, 'utf-8')).trim();
      return this.clientId;
    } catch {
      // Generate new ID
      this.clientId = crypto.randomUUID();
      try {
        await fs.promises.mkdir(this.stateDir, { recursive: true });
        await fs.promises.writeFile(idFile, this.clientId, 'utf-8');
      } catch {
        // Can't persist — use in-memory only
      }
      return this.clientId;
    }
  }

  /** Get the local cache instance (for testing/inspection). */
  getCache(): ThreatIntelCache {
    return this.cache;
  }

  // ── Cloud API methods ──

  private async cloudCheck(hash: string): Promise<ThreatCheckResult> {
    const url = `${this.config.apiUrl}/check/${encodeURIComponent(hash)}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return { known: false, confidence: 0, reportCount: 0 };
    }

    return response.json() as Promise<ThreatCheckResult>;
  }

  private async cloudReport(report: ThreatReport): Promise<void> {
    const url = `${this.config.apiUrl}/report`;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(report),
      signal: AbortSignal.timeout(5000),
    });
  }

  private async cloudFeed(since: string): Promise<ThreatFeedEntry[]> {
    const url = `${this.config.apiUrl}/feed?since=${encodeURIComponent(since)}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) return [];

    const data = await response.json() as { entries?: ThreatFeedEntry[] };
    return data.entries ?? [];
  }
}
