import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { EventScanResult } from '../security/types.js';

/**
 * Structured JSONL audit logger for CalGuard security scans.
 *
 * Writes one JSON line per scanned event to:
 *   ~/.calguard/logs/calguard-audit-YYYY-MM-DD.jsonl
 *
 * Each entry records: timestamp, eventId, organizerEmail,
 * riskScore, riskLevel, action taken, detections, and scan duration.
 */
export class AuditLogger {
  private logDir: string;
  private enabled: boolean;

  constructor(options?: { logDir?: string; enabled?: boolean }) {
    this.logDir = options?.logDir ?? path.join(os.homedir(), '.calguard', 'logs');
    this.enabled = options?.enabled ?? (process.env.CALGUARD_AUDIT_ENABLED !== 'false');
  }

  /**
   * Log a scan result. Fire-and-forget — errors are silently swallowed
   * so audit logging never breaks the scanning pipeline.
   */
  async logScan(scanResult: EventScanResult): Promise<void> {
    if (!this.enabled) return;

    try {
      await this.ensureLogDir();

      const entry: AuditEntry = {
        timestamp: scanResult.timestamp,
        eventId: scanResult.eventId,
        calendarId: scanResult.calendarId,
        organizerEmail: scanResult.organizerEmail,
        isExternalOrganizer: scanResult.isExternalOrganizer,
        riskScore: scanResult.overallRiskScore,
        riskLevel: scanResult.overallRiskLevel,
        action: scanResult.overallAction,
        detections: scanResult.fieldResults.flatMap(f =>
          f.detections.map(d => ({
            ruleId: d.ruleId,
            ruleName: d.ruleName,
            tier: d.tier,
            severity: d.severity,
            fieldName: f.fieldName,
          })),
        ),
        scanDurationMs: scanResult.scanDurationMs,
        fieldCount: scanResult.fieldResults.length,
      };

      const logFile = this.getLogFilePath();
      const line = JSON.stringify(entry) + '\n';

      await fs.promises.appendFile(logFile, line, 'utf-8');
    } catch {
      // Silent failure — audit logging must never break scanning
    }
  }

  /**
   * Log multiple scan results (e.g., from a list-events response).
   */
  async logBatch(scanResults: EventScanResult[]): Promise<void> {
    for (const result of scanResults) {
      await this.logScan(result);
    }
  }

  private getLogFilePath(): string {
    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    return path.join(this.logDir, `calguard-audit-${date}.jsonl`);
  }

  private async ensureLogDir(): Promise<void> {
    await fs.promises.mkdir(this.logDir, { recursive: true });
  }
}

/** Shape of a single audit log entry. */
interface AuditEntry {
  timestamp: string;
  eventId: string;
  calendarId: string;
  organizerEmail?: string;
  isExternalOrganizer: boolean;
  riskScore: number;
  riskLevel: string;
  action: string;
  detections: Array<{
    ruleId: string;
    ruleName: string;
    tier: string;
    severity: number;
    fieldName: string;
  }>;
  scanDurationMs: number;
  fieldCount: number;
}
