import type { GatekeepConfig } from './schema.js';

/**
 * Default Gatekeep configuration values.
 * Used as fallbacks when environment variables or config file are absent.
 */
export const DEFAULT_CONFIG: GatekeepConfig = {
  googleClientId: '',
  googleClientSecret: '',
  readOnly: true,
  thresholds: {
    suspicious: 0.30,
    dangerous: 0.60,
    critical: 0.85,
  },
  threatIntel: {
    enabled: false,
    apiUrl: 'https://api.gatekeep.dev/v1',
    syncIntervalMinutes: 15,
  },
  audit: {
    enabled: true,
  },
  quarantine: {
    ttlDays: 7,
  },
  logLevel: 'info',
};
