import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { EventScanResult } from '../types.js';

/** A quarantined event entry with original content preserved for review. */
export interface QuarantineEntry {
  eventId: string;
  calendarId: string;
  quarantinedAt: string;
  expiresAt: string;
  organizerEmail?: string;
  riskScore: number;
  riskLevel: string;
  action: string;
  /** Original field contents before redaction/blocking. */
  originalFields: Record<string, string>;
  /** Detection summary for quick reference. */
  detections: Array<{
    ruleId: string;
    ruleName: string;
    severity: number;
    fieldName: string;
  }>;
}

/**
 * Persistent store for blocked/redacted calendar event content.
 *
 * When Gatekeep blocks or redacts an event, the original content
 * is quarantined so administrators can inspect it via the
 * `gatekeep-view-quarantined` MCP tool.
 *
 * Storage: ~/.gatekeep/quarantine/<eventId>.json
 * Default TTL: 7 days
 */
export class QuarantineStore {
  private storeDir: string;
  private ttlMs: number;

  constructor(options?: { storeDir?: string; ttlDays?: number }) {
    this.storeDir = options?.storeDir ?? path.join(os.homedir(), '.gatekeep', 'quarantine');
    this.ttlMs = (options?.ttlDays ?? 7) * 24 * 60 * 60 * 1000;
  }

  /**
   * Quarantine an event's original content.
   * Called when action is BLOCK or REDACT.
   */
  async store(
    scanResult: EventScanResult,
    originalFields: Record<string, string>,
  ): Promise<void> {
    try {
      await this.ensureDir();

      const entry: QuarantineEntry = {
        eventId: scanResult.eventId,
        calendarId: scanResult.calendarId,
        quarantinedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + this.ttlMs).toISOString(),
        organizerEmail: scanResult.organizerEmail,
        riskScore: scanResult.overallRiskScore,
        riskLevel: scanResult.overallRiskLevel,
        action: scanResult.overallAction,
        originalFields,
        detections: scanResult.fieldResults.flatMap(f =>
          f.detections.map(d => ({
            ruleId: d.ruleId,
            ruleName: d.ruleName,
            severity: d.severity,
            fieldName: f.fieldName,
          })),
        ),
      };

      const filePath = this.entryPath(scanResult.eventId);
      await fs.promises.writeFile(filePath, JSON.stringify(entry, null, 2), 'utf-8');
    } catch {
      // Silent failure — quarantine is supplementary
    }
  }

  /**
   * Retrieve a quarantined event by ID.
   * Returns null if not found or expired.
   */
  async get(eventId: string): Promise<QuarantineEntry | null> {
    try {
      const filePath = this.entryPath(eventId);
      const content = await fs.promises.readFile(filePath, 'utf-8');
      const entry: QuarantineEntry = JSON.parse(content);

      // Check expiration
      if (new Date(entry.expiresAt) < new Date()) {
        await this.delete(eventId);
        return null;
      }

      return entry;
    } catch {
      return null;
    }
  }

  /**
   * List all non-expired quarantined entries.
   * Optionally filter by minimum risk level.
   */
  async list(options?: { minRiskLevel?: string }): Promise<QuarantineEntry[]> {
    try {
      await this.ensureDir();
      const files = await fs.promises.readdir(this.storeDir);
      const entries: QuarantineEntry[] = [];
      const now = new Date();

      for (const file of files) {
        if (!file.endsWith('.json')) continue;

        try {
          const content = await fs.promises.readFile(
            path.join(this.storeDir, file),
            'utf-8',
          );
          const entry: QuarantineEntry = JSON.parse(content);

          // Skip expired
          if (new Date(entry.expiresAt) < now) {
            await fs.promises.unlink(path.join(this.storeDir, file)).catch(() => {});
            continue;
          }

          // Apply risk level filter
          if (options?.minRiskLevel && !this.meetsMinRisk(entry.riskLevel, options.minRiskLevel)) {
            continue;
          }

          entries.push(entry);
        } catch {
          continue;
        }
      }

      // Sort by quarantined time descending (newest first)
      entries.sort((a, b) =>
        new Date(b.quarantinedAt).getTime() - new Date(a.quarantinedAt).getTime(),
      );

      return entries;
    } catch {
      return [];
    }
  }

  /** Delete a quarantined entry. */
  async delete(eventId: string): Promise<void> {
    try {
      await fs.promises.unlink(this.entryPath(eventId));
    } catch {
      // Already deleted or doesn't exist
    }
  }

  /** Remove all expired entries. */
  async cleanup(): Promise<number> {
    const files = await fs.promises.readdir(this.storeDir).catch(() => [] as string[]);
    const now = new Date();
    let removed = 0;

    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const content = await fs.promises.readFile(
          path.join(this.storeDir, file),
          'utf-8',
        );
        const entry: QuarantineEntry = JSON.parse(content);
        if (new Date(entry.expiresAt) < now) {
          await fs.promises.unlink(path.join(this.storeDir, file));
          removed++;
        }
      } catch {
        continue;
      }
    }

    return removed;
  }

  private entryPath(eventId: string): string {
    // Sanitize event ID for filesystem safety
    const safeId = eventId.replace(/[^a-zA-Z0-9_-]/g, '_');
    return path.join(this.storeDir, `${safeId}.json`);
  }

  private async ensureDir(): Promise<void> {
    await fs.promises.mkdir(this.storeDir, { recursive: true });
  }

  private meetsMinRisk(actual: string, min: string): boolean {
    const levels = ['safe', 'suspicious', 'dangerous', 'critical'];
    return levels.indexOf(actual) >= levels.indexOf(min);
  }
}
