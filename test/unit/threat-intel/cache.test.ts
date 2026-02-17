import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { ThreatIntelCache } from '../../../src/threat-intel/cache.js';
import type { ThreatFeedEntry } from '../../../src/threat-intel/types.js';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gatekeep-cache-test-'));
}

describe('ThreatIntelCache', () => {
  let cacheDir: string;
  let cache: ThreatIntelCache;

  beforeEach(() => {
    cacheDir = makeTempDir();
    cache = new ThreatIntelCache({ cacheDir, cacheTtlHours: 24 });
  });

  afterEach(async () => {
    await fs.promises.rm(cacheDir, { recursive: true, force: true });
  });

  describe('get/set', () => {
    it('returns null for unknown hash', async () => {
      const result = await cache.get('unknown-hash');
      expect(result).toBeNull();
    });

    it('stores and retrieves a check result', async () => {
      const result = {
        known: true,
        confidence: 0.85,
        reportCount: 5,
        firstSeen: '2024-01-01T00:00:00Z',
        lastSeen: '2024-06-15T00:00:00Z',
        category: 'prompt-injection',
      };

      await cache.set('abc123', result);
      const retrieved = await cache.get('abc123');

      expect(retrieved).not.toBeNull();
      expect(retrieved!.known).toBe(true);
      expect(retrieved!.confidence).toBe(0.85);
      expect(retrieved!.reportCount).toBe(5);
      expect(retrieved!.category).toBe('prompt-injection');
    });

    it('persists across instances', async () => {
      await cache.set('persist-test', {
        known: true,
        confidence: 0.9,
        reportCount: 10,
      });

      // Create new cache pointing to same dir
      const cache2 = new ThreatIntelCache({ cacheDir, cacheTtlHours: 24 });
      const result = await cache2.get('persist-test');

      expect(result).not.toBeNull();
      expect(result!.known).toBe(true);
      expect(result!.reportCount).toBe(10);
    });

    it('returns null for expired entries', async () => {
      // Use a very short TTL
      const shortCache = new ThreatIntelCache({ cacheDir, cacheTtlHours: 0 });

      await shortCache.set('will-expire', {
        known: true,
        confidence: 0.5,
        reportCount: 1,
      });

      // The entry should already be expired (TTL = 0 hours)
      // Need to wait a tick for the time to pass
      await new Promise(r => setTimeout(r, 10));

      // Read with a new instance that loads from file
      const freshCache = new ThreatIntelCache({ cacheDir, cacheTtlHours: 0 });
      const result = await freshCache.get('will-expire');
      expect(result).toBeNull();
    });

    it('stores negative results', async () => {
      await cache.set('not-threat', {
        known: false,
        confidence: 0,
        reportCount: 0,
      });

      const result = await cache.get('not-threat');
      expect(result).not.toBeNull();
      expect(result!.known).toBe(false);
    });
  });

  describe('importFeed', () => {
    it('imports feed entries as positive results', async () => {
      const feedEntries: ThreatFeedEntry[] = [
        {
          hash: 'feed-hash-1',
          hashType: 'content',
          confidence: 0.9,
          reportCount: 15,
          updatedAt: '2024-06-01T00:00:00Z',
          category: 'prompt-injection',
        },
        {
          hash: 'feed-hash-2',
          hashType: 'structural',
          confidence: 0.75,
          reportCount: 8,
          updatedAt: '2024-06-02T00:00:00Z',
        },
      ];

      const imported = await cache.importFeed(feedEntries);
      expect(imported).toBe(2);

      const result1 = await cache.get('feed-hash-1');
      expect(result1).not.toBeNull();
      expect(result1!.known).toBe(true);
      expect(result1!.confidence).toBe(0.9);

      const result2 = await cache.get('feed-hash-2');
      expect(result2).not.toBeNull();
      expect(result2!.known).toBe(true);
    });

    it('returns 0 for empty feed', async () => {
      const imported = await cache.importFeed([]);
      expect(imported).toBe(0);
    });
  });

  describe('prune', () => {
    it('removes expired entries', async () => {
      // Add entries via the cache API first (so they're loaded in memory)
      await cache.set('will-expire', { known: true, confidence: 0.5, reportCount: 1 });
      await cache.set('will-stay', { known: true, confidence: 0.9, reportCount: 10 });

      expect(cache.size).toBe(2);

      // Now overwrite the cache file with one expired entry and one valid
      const cacheFile = path.join(cacheDir, 'threat-intel.json');
      const data = [
        {
          hash: 'will-expire',
          result: { known: true, confidence: 0.5, reportCount: 1 },
          cachedAt: Date.now() - 100000,
          expiresAt: Date.now() - 1000, // expired
        },
        {
          hash: 'will-stay',
          result: { known: true, confidence: 0.9, reportCount: 10 },
          cachedAt: Date.now(),
          expiresAt: Date.now() + 86400000, // not expired
        },
      ];
      await fs.promises.writeFile(cacheFile, JSON.stringify(data));

      // Create a fresh cache instance so it loads the modified file
      // Use a large TTL so loading doesn't filter it out — but the file
      // already has entries with a past expiresAt
      const freshCache = new ThreatIntelCache({ cacheDir, cacheTtlHours: 24 });

      // The expired entry gets filtered during load (ensureLoaded).
      // So prune on a loaded cache should find 0 more to remove.
      // Instead, verify the expired entry is not accessible:
      const expired = await freshCache.get('will-expire');
      expect(expired).toBeNull();

      const valid = await freshCache.get('will-stay');
      expect(valid).not.toBeNull();
      expect(valid!.confidence).toBe(0.9);

      // Prune should report 0 since expired entries were already excluded during load
      const removed = await freshCache.prune();
      expect(removed).toBe(0);
      expect(freshCache.size).toBe(1);
    });
  });

  describe('size', () => {
    it('tracks entry count', async () => {
      await cache.set('a', { known: true, confidence: 0.5, reportCount: 1 });
      await cache.set('b', { known: false, confidence: 0, reportCount: 0 });
      expect(cache.size).toBe(2);
    });
  });
});
