import { describe, it, expect } from 'vitest';
import { RiskScorer } from '../../../src/security/scorer.js';
import { RiskLevel, SecurityAction, type Detection, type FieldScanResult } from '../../../src/security/types.js';

function makeDetection(overrides: Partial<Detection>): Detection {
  return {
    tier: 'structural',
    ruleId: 'TEST-001',
    ruleName: 'Test Rule',
    severity: 0.5,
    matchedContent: 'test',
    matchOffset: 0,
    matchLength: 4,
    confidence: 0.9,
    ...overrides,
  };
}

describe('RiskScorer', () => {
  const scorer = new RiskScorer();

  describe('scoreField', () => {
    it('returns SAFE for no detections', () => {
      const result = scorer.scoreField([]);
      expect(result.level).toBe(RiskLevel.SAFE);
      expect(result.action).toBe(SecurityAction.PASS);
      expect(result.score).toBe(0);
    });

    it('scores structural-only detection', () => {
      const detections = [makeDetection({ tier: 'structural', severity: 0.9 })];
      const result = scorer.scoreField(detections);
      // 0.9 * 0.40 = 0.36 -> SUSPICIOUS
      expect(result.score).toBeCloseTo(0.36, 1);
      expect(result.level).toBe(RiskLevel.SUSPICIOUS);
      expect(result.action).toBe(SecurityAction.FLAG);
    });

    it('applies multi-tier corroboration bonus', () => {
      const detections = [
        makeDetection({ tier: 'structural', severity: 0.9 }),
        makeDetection({ tier: 'contextual', severity: 0.8 }),
      ];
      const result = scorer.scoreField(detections);
      // Base: 0.9*0.40 + 0.8*0.45 = 0.36 + 0.36 = 0.72
      // 2-tier bonus: 0.72 * 1.15 = 0.828
      expect(result.score).toBeGreaterThan(0.72);
      expect(result.level).toBe(RiskLevel.DANGEROUS);
    });

    it('caps score at 1.0', () => {
      const detections = [
        makeDetection({ tier: 'structural', severity: 1.0 }),
        makeDetection({ tier: 'contextual', severity: 1.0 }),
        makeDetection({ tier: 'threat-intel', severity: 1.0 }),
      ];
      const result = scorer.scoreField(detections);
      expect(result.score).toBeLessThanOrEqual(1.0);
      expect(result.level).toBe(RiskLevel.CRITICAL);
      expect(result.action).toBe(SecurityAction.BLOCK);
    });

    it('adds convergence bonus for multiple detections in same tier', () => {
      const single = scorer.scoreField([
        makeDetection({ tier: 'structural', severity: 0.7 }),
      ]);
      const multiple = scorer.scoreField([
        makeDetection({ tier: 'structural', severity: 0.7, ruleId: 'A' }),
        makeDetection({ tier: 'structural', severity: 0.5, ruleId: 'B' }),
        makeDetection({ tier: 'structural', severity: 0.3, ruleId: 'C' }),
      ]);
      expect(multiple.score).toBeGreaterThan(single.score);
    });
  });

  describe('scoreEvent', () => {
    it('returns SAFE for no fields', () => {
      const result = scorer.scoreEvent([]);
      expect(result.level).toBe(RiskLevel.SAFE);
    });

    it('uses max field score for event', () => {
      const fields: FieldScanResult[] = [
        { fieldName: 'summary', originalLength: 10, riskScore: 0.1, riskLevel: RiskLevel.SAFE, action: SecurityAction.PASS, detections: [] },
        { fieldName: 'description', originalLength: 100, riskScore: 0.75, riskLevel: RiskLevel.DANGEROUS, action: SecurityAction.REDACT, detections: [] },
      ];
      const result = scorer.scoreEvent(fields);
      expect(result.score).toBe(0.75);
      expect(result.level).toBe(RiskLevel.DANGEROUS);
    });
  });

  describe('custom thresholds', () => {
    it('uses custom thresholds', () => {
      const customScorer = new RiskScorer({
        thresholdSuspicious: 0.10,
        thresholdDangerous: 0.40,
        thresholdCritical: 0.70,
      });

      const detections = [makeDetection({ tier: 'structural', severity: 0.5 })];
      const result = customScorer.scoreField(detections);
      // 0.5 * 0.40 = 0.20 -> with custom threshold 0.10 this is SUSPICIOUS
      expect(result.level).toBe(RiskLevel.SUSPICIOUS);
    });
  });
});
