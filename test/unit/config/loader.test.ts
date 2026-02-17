import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadConfig } from '../../../src/config/loader.js';

describe('loadConfig', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Set required env vars
    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
    // Prevent loading user's actual config file
    process.env.CALGUARD_CONFIG = '/nonexistent/config.json';
  });

  afterEach(() => {
    // Restore original environment
    process.env = { ...originalEnv };
  });

  it('loads defaults when only required env vars are set', () => {
    const config = loadConfig();
    expect(config.googleClientId).toBe('test-client-id');
    expect(config.googleClientSecret).toBe('test-client-secret');
    expect(config.readOnly).toBe(true);
    expect(config.thresholds.suspicious).toBe(0.30);
    expect(config.thresholds.dangerous).toBe(0.60);
    expect(config.thresholds.critical).toBe(0.85);
    expect(config.logLevel).toBe('info');
  });

  it('reads CALGUARD_READ_ONLY env var', () => {
    process.env.CALGUARD_READ_ONLY = 'false';
    const config = loadConfig();
    expect(config.readOnly).toBe(false);
  });

  it('reads risk threshold env vars', () => {
    process.env.CALGUARD_RISK_THRESHOLD_SUSPICIOUS = '0.20';
    process.env.CALGUARD_RISK_THRESHOLD_DANGEROUS = '0.50';
    process.env.CALGUARD_RISK_THRESHOLD_CRITICAL = '0.80';
    const config = loadConfig();
    expect(config.thresholds.suspicious).toBe(0.20);
    expect(config.thresholds.dangerous).toBe(0.50);
    expect(config.thresholds.critical).toBe(0.80);
  });

  it('reads threat intel env vars', () => {
    process.env.CALGUARD_THREAT_INTEL = 'true';
    process.env.CALGUARD_THREAT_INTEL_URL = 'https://custom.api.com/v1';
    const config = loadConfig();
    expect(config.threatIntel.enabled).toBe(true);
    expect(config.threatIntel.apiUrl).toBe('https://custom.api.com/v1');
  });

  it('reads audit env vars', () => {
    process.env.CALGUARD_AUDIT_ENABLED = 'false';
    const config = loadConfig();
    expect(config.audit.enabled).toBe(false);
  });

  it('reads log level env var', () => {
    process.env.CALGUARD_LOG_LEVEL = 'debug';
    const config = loadConfig();
    expect(config.logLevel).toBe('debug');
  });

  it('reads quarantine env vars', () => {
    process.env.CALGUARD_QUARANTINE_TTL_DAYS = '14';
    const config = loadConfig();
    expect(config.quarantine.ttlDays).toBe(14);
  });

  it('loads from config file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'calguard-config-test-'));
    const configFile = path.join(tmpDir, 'config.json');

    fs.writeFileSync(configFile, JSON.stringify({
      googleClientId: 'file-client-id',
      googleClientSecret: 'file-client-secret',
      readOnly: false,
      logLevel: 'warn',
    }));

    process.env.CALGUARD_CONFIG = configFile;
    // Remove env overrides to test file loading
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;

    const config = loadConfig();
    expect(config.googleClientId).toBe('file-client-id');
    expect(config.readOnly).toBe(false);
    expect(config.logLevel).toBe('warn');

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('env vars override config file values', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'calguard-config-test-'));
    const configFile = path.join(tmpDir, 'config.json');

    fs.writeFileSync(configFile, JSON.stringify({
      googleClientId: 'file-id',
      googleClientSecret: 'file-secret',
      logLevel: 'warn',
    }));

    process.env.CALGUARD_CONFIG = configFile;
    process.env.CALGUARD_LOG_LEVEL = 'error';

    const config = loadConfig();
    expect(config.logLevel).toBe('error'); // env wins

    fs.rmSync(tmpDir, { recursive: true });
  });
});
