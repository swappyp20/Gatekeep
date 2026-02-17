/**
 * Core security type definitions for CalGuard-AI.
 */

export enum RiskLevel {
  SAFE = 'safe',
  SUSPICIOUS = 'suspicious',
  DANGEROUS = 'dangerous',
  CRITICAL = 'critical',
}

export enum SecurityAction {
  PASS = 'pass',
  FLAG = 'flag',
  REDACT = 'redact',
  BLOCK = 'block',
}

/** A single detection from any tier. */
export interface Detection {
  tier: 'structural' | 'contextual' | 'threat-intel';
  ruleId: string;
  ruleName: string;
  severity: number;       // 0.0 - 1.0
  matchedContent: string;
  matchOffset: number;
  matchLength: number;
  confidence: number;     // 0.0 - 1.0
  metadata?: Record<string, unknown>;
}

/** Result of scanning a single text field. */
export interface FieldScanResult {
  fieldName: string;
  originalLength: number;
  riskScore: number;
  riskLevel: RiskLevel;
  action: SecurityAction;
  detections: Detection[];
  sanitizedContent?: string;
}

/** Result of scanning an entire calendar event. */
export interface EventScanResult {
  eventId: string;
  calendarId: string;
  organizerEmail?: string;
  isExternalOrganizer: boolean;
  overallRiskScore: number;
  overallRiskLevel: RiskLevel;
  overallAction: SecurityAction;
  fieldResults: FieldScanResult[];
  scanDurationMs: number;
  timestamp: string;
}

/** Context passed to detection tiers for contextual weighting. */
export interface ScanContext {
  fieldName: string;
  fieldType: 'title' | 'description' | 'location' | 'attendee_name' | 'attachment';
  organizerEmail?: string;
  organizerDomain?: string;
  isExternalOrganizer: boolean;
  calendarOwnerDomain?: string;
}

/** Operational limits to prevent abuse. */
export const SECURITY_LIMITS = {
  maxFieldLength: 50_000,
  maxEventsPerScan: 100,
  maxDetectionsPerField: 50,
  maxBase64DecodeDepth: 3,
  maxRegexTimeout: 100,
  maxTotalScanTime: 5_000,
} as const;
