import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ThreatIntelClient } from '../../../src/threat-intel/client.js';
import type { ThreatFingerprint } from '../../../src/threat-intel/types.js';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'calguard-client-test-'));
}

describe('ThreatIntelClient', () => {
  let stateDir: string;

  beforeEach(() => {
    stateDir = makeTempDir();
  });

  afterEach(async () => {
    await fs.promises.rm(stateDir, { recursive: true, force: true });
  });

  describe('with cloud disabled', () => {
    it('check returns negative result without network call', async () => {
      const client = new ThreatIntelClient({
        enabled: false,
        stateDir,
      });

      const fp: ThreatFingerprint = {
        contentHash: 'a'.repeat(64),
        structuralHash: 'b'.repeat(64),
        patternIds: ['STRUCT-003'],
        riskScore: 0.85,
      };

      const result = await client.check(fp);
      expect(result.known).toBe(false);
      expect(result.confidence).toBe(0);
    });

    it('report silently no-ops', async () => {
      const client = new ThreatIntelClient({
        enabled: false,
        stateDir,
      });

      // Should not throw
      await client.report({
        contentHash: 'a'.repeat(64),
        structuralHash: 'b'.repeat(64),
        patternIds: [],
        riskScore: 0.9,
      });
    });

    it('syncFeed returns 0', async () => {
      const client = new ThreatIntelClient({
        enabled: false,
        stateDir,
      });

      const imported = await client.syncFeed();
      expect(imported).toBe(0);
    });
  });

  describe('check with cached data', () => {
    it('returns cached positive result without network call', async () => {
      const client = new ThreatIntelClient({
        enabled: false, // no cloud, but we seed the cache
        stateDir,
      });

      // Seed the cache directly
      const cache = client.getCache();
      await cache.set('known-content-hash', {
        known: true,
        confidence: 0.9,
        reportCount: 10,
        category: 'prompt-injection',
      });

      const fp: ThreatFingerprint = {
        contentHash: 'known-content-hash',
        structuralHash: 'unknown-structural-hash',
        patternIds: [],
        riskScore: 0,
      };

      const result = await client.check(fp);
      expect(result.known).toBe(true);
      expect(result.confidence).toBe(0.9);
    });

    it('falls back to structural hash cache', async () => {
      const client = new ThreatIntelClient({
        enabled: false,
        stateDir,
      });

      const cache = client.getCache();
      await cache.set('known-structural-hash', {
        known: true,
        confidence: 0.75,
        reportCount: 5,
      });

      const fp: ThreatFingerprint = {
        contentHash: 'unknown-content-hash',
        structuralHash: 'known-structural-hash',
        patternIds: [],
        riskScore: 0,
      };

      const result = await client.check(fp);
      expect(result.known).toBe(true);
      expect(result.confidence).toBe(0.75);
    });
  });

  describe('getClientId', () => {
    it('generates and persists a UUID', async () => {
      const client = new ThreatIntelClient({ enabled: false, stateDir });
      const id = await client.getClientId();

      // UUID v4 format
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

      // Should persist to file
      const savedId = await fs.promises.readFile(
        path.join(stateDir, 'client-id'),
        'utf-8',
      );
      expect(savedId.trim()).toBe(id);
    });

    it('reuses existing client ID', async () => {
      const client = new ThreatIntelClient({ enabled: false, stateDir });
      const id1 = await client.getClientId();
      const id2 = await client.getClientId();
      expect(id1).toBe(id2);
    });

    it('loads persisted ID on new instance', async () => {
      const client1 = new ThreatIntelClient({ enabled: false, stateDir });
      const id1 = await client1.getClientId();

      const client2 = new ThreatIntelClient({ enabled: false, stateDir });
      const id2 = await client2.getClientId();

      expect(id1).toBe(id2);
    });
  });

  describe('getFingerprinter', () => {
    it('returns an EventFingerprinter instance', () => {
      const client = new ThreatIntelClient({ enabled: false, stateDir });
      const fp = client.getFingerprinter();
      expect(fp).toBeDefined();
      expect(typeof fp.computeContentHash).toBe('function');
      expect(typeof fp.computeStructuralHash).toBe('function');
    });
  });

  describe('with cloud enabled (unreachable)', () => {
    it('check gracefully degrades on network error', async () => {
      const client = new ThreatIntelClient({
        enabled: true,
        apiUrl: 'http://localhost:19999', // unreachable
        stateDir,
      });

      const fp: ThreatFingerprint = {
        contentHash: 'a'.repeat(64),
        structuralHash: 'b'.repeat(64),
        patternIds: [],
        riskScore: 0.5,
      };

      const result = await client.check(fp);
      expect(result.known).toBe(false);
    });

    it('report gracefully degrades on network error', async () => {
      const client = new ThreatIntelClient({
        enabled: true,
        apiUrl: 'http://localhost:19999',
        stateDir,
      });

      // Should not throw
      await client.report({
        contentHash: 'a'.repeat(64),
        structuralHash: 'b'.repeat(64),
        patternIds: ['STRUCT-003'],
        riskScore: 0.9,
      });
    });

    it('syncFeed gracefully degrades on network error', async () => {
      const client = new ThreatIntelClient({
        enabled: true,
        apiUrl: 'http://localhost:19999',
        stateDir,
        syncIntervalMinutes: 0, // force sync
      });

      const imported = await client.syncFeed();
      expect(imported).toBe(0);
    });
  });
});
