import type { Detection, ScanContext } from '../types.js';

/**
 * Abstract interface for all detection tiers.
 * New tiers (ML classifier, etc.) implement this interface.
 */
export interface DetectionTier {
  readonly tierName: string;
  analyze(text: string, context: ScanContext): Detection[] | Promise<Detection[]>;
}
