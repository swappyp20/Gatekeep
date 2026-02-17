import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { CachedThreatEntry, ThreatCheckResult, ThreatFeedEntry } from './types.js';

/**
 * Local file-based cache for threat intelligence lookups.
 *
 * Stores check results and feed entries at:
 *   ~/.gatekeep/cache/threat-intel.json
 *
 * Entries are TTL-based and automatically pruned on read.
 */
export class ThreatIntelCache {
  private cacheDir: string;
  private cacheFile: string;
  private cacheTtlMs: number;
  private entries: Map<string, CachedThreatEntry>;
  private loaded: boolean;

  constructor(options?: { cacheDir?: string; cacheTtlHours?: number }) {
    this.cacheDir = options?.cacheDir ?? path.join(os.homedir(), '.gatekeep', 'cache');
    this.cacheFile = path.join(this.cacheDir, 'threat-intel.json');
    this.cacheTtlMs = (options?.cacheTtlHours ?? 24) * 60 * 60 * 1000;
    this.entries = new Map();
    this.loaded = false;
  }

  /**
   * Check if a hash exists in the local cache.
   * Returns the cached result if found and not expired, null otherwise.
   */
  async get(hash: string): Promise<ThreatCheckResult | null> {
    await this.ensureLoaded();

    const entry = this.entries.get(hash);
    if (!entry) return null;

    if (entry.expiresAt < Date.now()) {
      this.entries.delete(hash);
      await this.persist();
      return null;
    }

    return entry.result;
  }

  /**
   * Store a check result in the local cache.
   */
  async set(hash: string, result: ThreatCheckResult): Promise<void> {
    await this.ensureLoaded();

    const entry: CachedThreatEntry = {
      hash,
      result,
      cachedAt: Date.now(),
      expiresAt: Date.now() + this.cacheTtlMs,
    };

    this.entries.set(hash, entry);
    await this.persist();
  }

  /**
   * Import entries from a threat feed sync.
   * Feed entries are stored as positive check results in the cache.
   */
  async importFeed(feedEntries: ThreatFeedEntry[]): Promise<number> {
    await this.ensureLoaded();

    let imported = 0;
    for (const entry of feedEntries) {
      const result: ThreatCheckResult = {
        known: true,
        confidence: entry.confidence,
        reportCount: entry.reportCount,
        lastSeen: entry.updatedAt,
        category: entry.category,
      };

      this.entries.set(entry.hash, {
        hash: entry.hash,
        result,
        cachedAt: Date.now(),
        expiresAt: Date.now() + this.cacheTtlMs,
      });
      imported++;
    }

    await this.persist();
    return imported;
  }

  /**
   * Remove all expired entries.
   */
  async prune(): Promise<number> {
    await this.ensureLoaded();
    const now = Date.now();
    let removed = 0;

    for (const [hash, entry] of this.entries) {
      if (entry.expiresAt < now) {
        this.entries.delete(hash);
        removed++;
      }
    }

    if (removed > 0) await this.persist();
    return removed;
  }

  /** Number of cached entries. */
  get size(): number {
    return this.entries.size;
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;

    try {
      await fs.promises.mkdir(this.cacheDir, { recursive: true });
      const content = await fs.promises.readFile(this.cacheFile, 'utf-8');
      const data: CachedThreatEntry[] = JSON.parse(content);

      const now = Date.now();
      for (const entry of data) {
        if (entry.expiresAt > now) {
          this.entries.set(entry.hash, entry);
        }
      }
    } catch {
      // No cache file or invalid — start fresh
    }

    this.loaded = true;
  }

  private async persist(): Promise<void> {
    try {
      await fs.promises.mkdir(this.cacheDir, { recursive: true });
      const data = [...this.entries.values()];
      await fs.promises.writeFile(
        this.cacheFile,
        JSON.stringify(data, null, 2),
        'utf-8',
      );
    } catch {
      // Silent failure — cache is supplementary
    }
  }
}
