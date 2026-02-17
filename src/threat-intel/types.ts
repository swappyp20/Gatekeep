/**
 * Types for the CalGuard Cloud Threat Intelligence system.
 *
 * Privacy-first: only cryptographic fingerprints are exchanged
 * with the cloud service — never raw calendar content.
 */

/** Privacy-safe fingerprint of an event's content. */
export interface ThreatFingerprint {
  /** SHA-256 of normalized description text (catches exact duplicates). */
  contentHash: string;
  /** SHA-256 of structural "shape" (catches variants of same attack). */
  structuralHash: string;
  /** Detected pattern rule IDs (e.g., ['STRUCT-003', 'CTX-001']). */
  patternIds: string[];
  /** Composite risk score from local analysis. */
  riskScore: number;
  /** Organizer domain (not full email) for domain-level threat tracking. */
  organizerDomain?: string;
}

/** Report sent to the cloud service for DANGEROUS+ detections. */
export interface ThreatReport {
  /** Anonymous client identifier (UUID v4, generated on first run). */
  clientId: string;
  /** The event fingerprint. */
  fingerprint: ThreatFingerprint;
  /** ISO 8601 timestamp. */
  reportedAt: string;
}

/** Response from a cloud threat check. */
export interface ThreatCheckResult {
  /** Whether this hash is a known threat. */
  known: boolean;
  /** Confidence level if known (0.0 - 1.0). */
  confidence: number;
  /** Number of independent reports for this hash. */
  reportCount: number;
  /** When the threat was first reported (ISO 8601). */
  firstSeen?: string;
  /** When the threat was last reported (ISO 8601). */
  lastSeen?: string;
  /** Community-assigned threat category. */
  category?: string;
}

/** A threat hash entry from the feed sync. */
export interface ThreatFeedEntry {
  /** The hash (content or structural). */
  hash: string;
  /** Hash type: 'content' or 'structural'. */
  hashType: 'content' | 'structural';
  /** Confidence level (0.0 - 1.0). */
  confidence: number;
  /** Number of reports. */
  reportCount: number;
  /** ISO 8601 timestamp of when it was added/updated in the feed. */
  updatedAt: string;
  /** Threat category. */
  category?: string;
}

/** Local cache entry wrapping a check result with TTL. */
export interface CachedThreatEntry {
  /** The hash that was checked. */
  hash: string;
  /** The check result. */
  result: ThreatCheckResult;
  /** When this cache entry was written (epoch ms). */
  cachedAt: number;
  /** When this cache entry expires (epoch ms). */
  expiresAt: number;
}
