import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { CalGuardConfigSchema, type CalGuardConfig } from './schema.js';

/**
 * Load CalGuard configuration from environment variables and optional config file.
 *
 * Priority: Environment variables > config file > defaults.
 *
 * Config file locations (first found wins):
 *   1. CALGUARD_CONFIG env var
 *   2. ~/.calguard/config.json
 */
export function loadConfig(): CalGuardConfig {
  const fileConfig = loadConfigFile();
  const envConfig = loadEnvConfig();

  // Merge: env overrides file, schema provides defaults
  const fileCfg = (fileConfig ?? {}) as Record<string, unknown>;
  const envCfg = envConfig as Record<string, unknown>;

  const merged: Record<string, unknown> = {
    ...fileCfg,
    ...envCfg,
    thresholds: {
      ...(fileCfg.thresholds as Record<string, unknown> | undefined),
      ...(envCfg.thresholds as Record<string, unknown> | undefined),
    },
    threatIntel: {
      ...(fileCfg.threatIntel as Record<string, unknown> | undefined),
      ...(envCfg.threatIntel as Record<string, unknown> | undefined),
    },
    audit: {
      ...(fileCfg.audit as Record<string, unknown> | undefined),
      ...(envCfg.audit as Record<string, unknown> | undefined),
    },
    quarantine: {
      ...(fileCfg.quarantine as Record<string, unknown> | undefined),
      ...(envCfg.quarantine as Record<string, unknown> | undefined),
    },
  };

  const result = CalGuardConfigSchema.safeParse(merged);

  if (!result.success) {
    const errors = result.error.issues
      .map(i => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    process.stderr.write(`[CalGuard] Configuration errors:\n${errors}\n`);
    process.stderr.write('[CalGuard] Using defaults where possible.\n');

    // Try again with just defaults — will only fail if required fields are missing
    return CalGuardConfigSchema.parse({
      googleClientId: process.env.GOOGLE_CLIENT_ID ?? '',
      googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
    });
  }

  return result.data;
}

function loadConfigFile(): Record<string, unknown> | undefined {
  const configPath = process.env.CALGUARD_CONFIG ??
    path.join(os.homedir(), '.calguard', 'config.json');

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(content);
  } catch {
    return undefined;
  }
}

function loadEnvConfig(): Record<string, unknown> {
  const config: Record<string, unknown> = {};

  if (process.env.GOOGLE_CLIENT_ID) config.googleClientId = process.env.GOOGLE_CLIENT_ID;
  if (process.env.GOOGLE_CLIENT_SECRET) config.googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;

  if (process.env.CALGUARD_READ_ONLY !== undefined) {
    config.readOnly = process.env.CALGUARD_READ_ONLY !== 'false';
  }

  if (process.env.CALGUARD_LOG_LEVEL) {
    config.logLevel = process.env.CALGUARD_LOG_LEVEL;
  }

  // Thresholds
  const thresholds: Record<string, number> = {};
  if (process.env.CALGUARD_RISK_THRESHOLD_SUSPICIOUS) {
    thresholds.suspicious = parseFloat(process.env.CALGUARD_RISK_THRESHOLD_SUSPICIOUS);
  }
  if (process.env.CALGUARD_RISK_THRESHOLD_DANGEROUS) {
    thresholds.dangerous = parseFloat(process.env.CALGUARD_RISK_THRESHOLD_DANGEROUS);
  }
  if (process.env.CALGUARD_RISK_THRESHOLD_CRITICAL) {
    thresholds.critical = parseFloat(process.env.CALGUARD_RISK_THRESHOLD_CRITICAL);
  }
  if (Object.keys(thresholds).length > 0) config.thresholds = thresholds;

  // Threat Intel
  const threatIntel: Record<string, unknown> = {};
  if (process.env.CALGUARD_THREAT_INTEL !== undefined) {
    threatIntel.enabled = process.env.CALGUARD_THREAT_INTEL === 'true';
  }
  if (process.env.CALGUARD_THREAT_INTEL_URL) {
    threatIntel.apiUrl = process.env.CALGUARD_THREAT_INTEL_URL;
  }
  if (Object.keys(threatIntel).length > 0) config.threatIntel = threatIntel;

  // Audit
  const audit: Record<string, unknown> = {};
  if (process.env.CALGUARD_AUDIT_ENABLED !== undefined) {
    audit.enabled = process.env.CALGUARD_AUDIT_ENABLED !== 'false';
  }
  if (process.env.CALGUARD_AUDIT_DIR) {
    audit.logDir = process.env.CALGUARD_AUDIT_DIR;
  }
  if (Object.keys(audit).length > 0) config.audit = audit;

  // Quarantine
  const quarantine: Record<string, unknown> = {};
  if (process.env.CALGUARD_QUARANTINE_TTL_DAYS) {
    quarantine.ttlDays = parseInt(process.env.CALGUARD_QUARANTINE_TTL_DAYS, 10);
  }
  if (process.env.CALGUARD_QUARANTINE_DIR) {
    quarantine.storeDir = process.env.CALGUARD_QUARANTINE_DIR;
  }
  if (Object.keys(quarantine).length > 0) config.quarantine = quarantine;

  return config;
}
