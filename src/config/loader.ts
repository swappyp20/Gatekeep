import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { GatekeepConfigSchema, type GatekeepConfig } from './schema.js';

/**
 * Load Gatekeep configuration from environment variables and optional config file.
 *
 * Priority: Environment variables > config file > defaults.
 *
 * Config file locations (first found wins):
 *   1. GATEKEEP_CONFIG env var
 *   2. ~/.gatekeep/config.json
 */
export function loadConfig(): GatekeepConfig {
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

  const result = GatekeepConfigSchema.safeParse(merged);

  if (!result.success) {
    const errors = result.error.issues
      .map(i => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    process.stderr.write(`[Gatekeep] Configuration errors:\n${errors}\n`);
    process.stderr.write('[Gatekeep] Using defaults where possible.\n');

    // Try again with just defaults — will only fail if required fields are missing
    return GatekeepConfigSchema.parse({
      googleClientId: process.env.GOOGLE_CLIENT_ID ?? '',
      googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
    });
  }

  return result.data;
}

function loadConfigFile(): Record<string, unknown> | undefined {
  const configPath = process.env.GATEKEEP_CONFIG ??
    path.join(os.homedir(), '.gatekeep', 'config.json');

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

  if (process.env.GATEKEEP_READ_ONLY !== undefined) {
    config.readOnly = process.env.GATEKEEP_READ_ONLY !== 'false';
  }

  if (process.env.GATEKEEP_LOG_LEVEL) {
    config.logLevel = process.env.GATEKEEP_LOG_LEVEL;
  }

  // Thresholds
  const thresholds: Record<string, number> = {};
  if (process.env.GATEKEEP_RISK_THRESHOLD_SUSPICIOUS) {
    thresholds.suspicious = parseFloat(process.env.GATEKEEP_RISK_THRESHOLD_SUSPICIOUS);
  }
  if (process.env.GATEKEEP_RISK_THRESHOLD_DANGEROUS) {
    thresholds.dangerous = parseFloat(process.env.GATEKEEP_RISK_THRESHOLD_DANGEROUS);
  }
  if (process.env.GATEKEEP_RISK_THRESHOLD_CRITICAL) {
    thresholds.critical = parseFloat(process.env.GATEKEEP_RISK_THRESHOLD_CRITICAL);
  }
  if (Object.keys(thresholds).length > 0) config.thresholds = thresholds;

  // Threat Intel
  const threatIntel: Record<string, unknown> = {};
  if (process.env.GATEKEEP_THREAT_INTEL !== undefined) {
    threatIntel.enabled = process.env.GATEKEEP_THREAT_INTEL === 'true';
  }
  if (process.env.GATEKEEP_THREAT_INTEL_URL) {
    threatIntel.apiUrl = process.env.GATEKEEP_THREAT_INTEL_URL;
  }
  if (Object.keys(threatIntel).length > 0) config.threatIntel = threatIntel;

  // Audit
  const audit: Record<string, unknown> = {};
  if (process.env.GATEKEEP_AUDIT_ENABLED !== undefined) {
    audit.enabled = process.env.GATEKEEP_AUDIT_ENABLED !== 'false';
  }
  if (process.env.GATEKEEP_AUDIT_DIR) {
    audit.logDir = process.env.GATEKEEP_AUDIT_DIR;
  }
  if (Object.keys(audit).length > 0) config.audit = audit;

  // Quarantine
  const quarantine: Record<string, unknown> = {};
  if (process.env.GATEKEEP_QUARANTINE_TTL_DAYS) {
    quarantine.ttlDays = parseInt(process.env.GATEKEEP_QUARANTINE_TTL_DAYS, 10);
  }
  if (process.env.GATEKEEP_QUARANTINE_DIR) {
    quarantine.storeDir = process.env.GATEKEEP_QUARANTINE_DIR;
  }
  if (Object.keys(quarantine).length > 0) config.quarantine = quarantine;

  return config;
}
