import { describe, it, expect } from 'vitest';
import { CalGuardConfigSchema } from '../../../src/config/schema.js';

describe('CalGuardConfigSchema', () => {
  it('accepts minimal valid config', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'test-client-id',
      googleClientSecret: 'test-client-secret',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.readOnly).toBe(true);
      expect(result.data.thresholds.suspicious).toBe(0.30);
      expect(result.data.thresholds.dangerous).toBe(0.60);
      expect(result.data.thresholds.critical).toBe(0.85);
      expect(result.data.threatIntel.enabled).toBe(false);
      expect(result.data.audit.enabled).toBe(true);
      expect(result.data.quarantine.ttlDays).toBe(7);
      expect(result.data.logLevel).toBe('info');
    }
  });

  it('accepts full config with all fields', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'client-id',
      googleClientSecret: 'client-secret',
      readOnly: false,
      thresholds: { suspicious: 0.25, dangerous: 0.55, critical: 0.80 },
      threatIntel: {
        enabled: true,
        apiUrl: 'https://custom.api.com/v1',
        syncIntervalMinutes: 30,
      },
      audit: { enabled: false, logDir: '/custom/logs' },
      quarantine: { ttlDays: 14, storeDir: '/custom/quarantine' },
      logLevel: 'debug',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.readOnly).toBe(false);
      expect(result.data.thresholds.suspicious).toBe(0.25);
      expect(result.data.threatIntel.enabled).toBe(true);
      expect(result.data.audit.enabled).toBe(false);
      expect(result.data.quarantine.ttlDays).toBe(14);
      expect(result.data.logLevel).toBe('debug');
    }
  });

  it('rejects empty googleClientId', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: '',
      googleClientSecret: 'secret',
    });
    expect(result.success).toBe(false);
  });

  it('rejects thresholds out of order', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'id',
      googleClientSecret: 'secret',
      thresholds: { suspicious: 0.70, dangerous: 0.50, critical: 0.85 },
    });
    expect(result.success).toBe(false);
  });

  it('rejects threshold values outside 0-1 range', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'id',
      googleClientSecret: 'secret',
      thresholds: { suspicious: -0.1, dangerous: 0.60, critical: 0.85 },
    });
    expect(result.success).toBe(false);
  });

  it('rejects invalid log level', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'id',
      googleClientSecret: 'secret',
      logLevel: 'verbose',
    });
    expect(result.success).toBe(false);
  });

  it('rejects invalid threat intel URL', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'id',
      googleClientSecret: 'secret',
      threatIntel: { enabled: true, apiUrl: 'not-a-url' },
    });
    expect(result.success).toBe(false);
  });

  it('rejects negative quarantine TTL', () => {
    const result = CalGuardConfigSchema.safeParse({
      googleClientId: 'id',
      googleClientSecret: 'secret',
      quarantine: { ttlDays: -1 },
    });
    expect(result.success).toBe(false);
  });
});
