import { z } from 'zod';

/**
 * Zod schema for CalGuard configuration.
 * Used to validate environment variables and config file values.
 */
export const CalGuardConfigSchema = z.object({
  /** Google OAuth */
  googleClientId: z.string().min(1),
  googleClientSecret: z.string().min(1),

  /** Read-only mode — disables write calendar tools. */
  readOnly: z.boolean().default(true),

  /** Risk score thresholds (0.0 - 1.0). */
  thresholds: z.object({
    suspicious: z.number().min(0).max(1).default(0.30),
    dangerous: z.number().min(0).max(1).default(0.60),
    critical: z.number().min(0).max(1).default(0.85),
  }).default({}),

  /** Cloud threat intelligence. */
  threatIntel: z.object({
    enabled: z.boolean().default(false),
    apiUrl: z.string().url().default('https://api.calguard.dev/v1'),
    syncIntervalMinutes: z.number().int().positive().default(15),
  }).default({}),

  /** Audit logging. */
  audit: z.object({
    enabled: z.boolean().default(true),
    logDir: z.string().optional(),
  }).default({}),

  /** Quarantine store. */
  quarantine: z.object({
    ttlDays: z.number().int().positive().default(7),
    storeDir: z.string().optional(),
  }).default({}),

  /** Logging level. */
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
}).refine(
  (cfg) => cfg.thresholds.suspicious < cfg.thresholds.dangerous &&
           cfg.thresholds.dangerous < cfg.thresholds.critical,
  { message: 'Thresholds must be in ascending order: suspicious < dangerous < critical' },
);

export type CalGuardConfig = z.infer<typeof CalGuardConfigSchema>;
