import {
  RiskLevel,
  SecurityAction,
  type Detection,
  type FieldScanResult,
} from './types.js';

export interface ScoringConfig {
  thresholdSuspicious: number;
  thresholdDangerous: number;
  thresholdCritical: number;
}

const DEFAULT_CONFIG: ScoringConfig = {
  thresholdSuspicious: 0.30,
  thresholdDangerous: 0.60,
  thresholdCritical: 0.85,
};

/** Weights for each detection tier (must sum to 1.0). */
const TIER_WEIGHTS: Record<string, number> = {
  structural: 0.40,
  contextual: 0.45,
  'threat-intel': 0.15,
};

/**
 * Combines detections from multiple tiers into a single risk score.
 */
export class RiskScorer {
  private config: ScoringConfig;

  constructor(config?: Partial<ScoringConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Score a single field from its detections grouped by tier.
   */
  scoreField(detections: Detection[]): {
    score: number;
    level: RiskLevel;
    action: SecurityAction;
  } {
    if (detections.length === 0) {
      return { score: 0, level: RiskLevel.SAFE, action: SecurityAction.PASS };
    }

    // Group detections by tier
    const byTier = new Map<string, Detection[]>();
    for (const d of detections) {
      const existing = byTier.get(d.tier) ?? [];
      existing.push(d);
      byTier.set(d.tier, existing);
    }

    // Per-tier scoring: max severity + convergence bonus
    const tierScores = new Map<string, number>();
    for (const [tier, tierDetections] of byTier) {
      const maxSeverity = Math.max(...tierDetections.map(d => d.severity));
      const convergenceBonus = Math.min(
        (tierDetections.length - 1) * 0.05,
        0.15,
      );
      tierScores.set(tier, Math.min(maxSeverity + convergenceBonus, 1.0));
    }

    // Weighted combination
    let compositeScore = 0;
    for (const [tier, weight] of Object.entries(TIER_WEIGHTS)) {
      compositeScore += (tierScores.get(tier) ?? 0) * weight;
    }

    // Multi-tier corroboration bonus
    const firingTiers = [...tierScores.values()].filter(s => s > 0).length;
    if (firingTiers >= 2) compositeScore = Math.min(compositeScore * 1.15, 1.0);
    if (firingTiers >= 3) compositeScore = Math.min(compositeScore * 1.10, 1.0);

    const level = this.scoreToLevel(compositeScore);
    const action = this.levelToAction(level);

    return { score: compositeScore, level, action };
  }

  /**
   * Score an entire event by aggregating field scores.
   * Event risk = max field risk.
   */
  scoreEvent(fieldResults: FieldScanResult[]): {
    score: number;
    level: RiskLevel;
    action: SecurityAction;
  } {
    if (fieldResults.length === 0) {
      return { score: 0, level: RiskLevel.SAFE, action: SecurityAction.PASS };
    }

    const maxScore = Math.max(...fieldResults.map(f => f.riskScore));
    const level = this.scoreToLevel(maxScore);
    const action = this.levelToAction(level);

    return { score: maxScore, level, action };
  }

  private scoreToLevel(score: number): RiskLevel {
    if (score >= this.config.thresholdCritical) return RiskLevel.CRITICAL;
    if (score >= this.config.thresholdDangerous) return RiskLevel.DANGEROUS;
    if (score >= this.config.thresholdSuspicious) return RiskLevel.SUSPICIOUS;
    return RiskLevel.SAFE;
  }

  private levelToAction(level: RiskLevel): SecurityAction {
    switch (level) {
      case RiskLevel.CRITICAL: return SecurityAction.BLOCK;
      case RiskLevel.DANGEROUS: return SecurityAction.REDACT;
      case RiskLevel.SUSPICIOUS: return SecurityAction.FLAG;
      case RiskLevel.SAFE: return SecurityAction.PASS;
    }
  }
}
