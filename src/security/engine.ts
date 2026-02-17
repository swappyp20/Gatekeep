import type { DetectionTier } from './tiers/base-tier.js';
import { StructuralAnalyzer } from './tiers/structural.js';
import { ContextualAnalyzer } from './tiers/contextual.js';
import { ThreatIntelTier } from './tiers/threat-intel.js';
import type { ThreatIntelClientConfig } from '../threat-intel/client.js';
import { RiskScorer, type ScoringConfig } from './scorer.js';
import { ContentRedactor } from './actions/redactor.js';
import {
  type Detection,
  type FieldScanResult,
  type EventScanResult,
  type ScanContext,
  RiskLevel,
  SecurityAction,
  SECURITY_LIMITS,
} from './types.js';

/** A calendar event in the shape Gatekeep expects. */
export interface CalendarEvent {
  id: string;
  calendarId?: string;
  summary?: string;
  description?: string;
  location?: string;
  organizer?: { email?: string };
  attendees?: Array<{ displayName?: string; email?: string }>;
  attachments?: Array<{ title?: string }>;
}

/**
 * Orchestrates the sanitization pipeline:
 *   Extract fields → Run tiers → Score → Redact/Annotate
 */
export interface EngineConfig {
  scoring?: Partial<ScoringConfig>;
  threatIntel?: Partial<ThreatIntelClientConfig>;
}

export class SanitizationEngine {
  private tiers: DetectionTier[];
  private scorer: RiskScorer;
  private redactor: ContentRedactor;
  private threatIntelTier?: ThreatIntelTier;

  constructor(config?: Partial<ScoringConfig> | EngineConfig) {
    // Support both old (ScoringConfig) and new (EngineConfig) constructor signatures
    let scoringConfig: Partial<ScoringConfig> | undefined;
    let threatIntelConfig: Partial<ThreatIntelClientConfig> | undefined;

    if (config && 'scoring' in config) {
      scoringConfig = (config as EngineConfig).scoring;
      threatIntelConfig = (config as EngineConfig).threatIntel;
    } else {
      scoringConfig = config as Partial<ScoringConfig> | undefined;
    }

    this.tiers = [new StructuralAnalyzer(), new ContextualAnalyzer()];

    // Add Tier 3 if threat intel is configured
    if (threatIntelConfig?.enabled) {
      this.threatIntelTier = new ThreatIntelTier(threatIntelConfig);
      this.tiers.push(this.threatIntelTier);
    }

    this.scorer = new RiskScorer(scoringConfig);
    this.redactor = new ContentRedactor();
  }

  /** Get the threat intel tier (if enabled) for reporting/sync. */
  getThreatIntelTier(): ThreatIntelTier | undefined {
    return this.threatIntelTier;
  }

  /**
   * Scan a single calendar event through all detection tiers.
   */
  async scanEvent(
    event: CalendarEvent,
    calendarOwnerDomain?: string,
  ): Promise<{ result: EventScanResult; sanitizedEvent: CalendarEvent }> {
    const startTime = performance.now();

    const organizerDomain = this.extractDomain(event.organizer?.email);
    const isExternal = !!(
      calendarOwnerDomain &&
      organizerDomain &&
      organizerDomain !== calendarOwnerDomain
    );

    const scannableFields = this.extractScannableFields(event);
    const fieldResults: FieldScanResult[] = [];

    for (const { fieldName, fieldType, content } of scannableFields) {
      if (!content || content.trim().length === 0) continue;

      const context: ScanContext = {
        fieldName,
        fieldType,
        organizerEmail: event.organizer?.email,
        organizerDomain,
        isExternalOrganizer: isExternal,
        calendarOwnerDomain,
      };

      const fieldResult = await this.scanField(content, context);
      fieldResults.push(fieldResult);
    }

    const eventScore = this.scorer.scoreEvent(fieldResults);

    const result: EventScanResult = {
      eventId: event.id,
      calendarId: event.calendarId ?? '',
      organizerEmail: event.organizer?.email,
      isExternalOrganizer: isExternal,
      overallRiskScore: eventScore.score,
      overallRiskLevel: eventScore.level,
      overallAction: eventScore.action,
      fieldResults,
      scanDurationMs: performance.now() - startTime,
      timestamp: new Date().toISOString(),
    };

    const sanitizedEvent = this.applySanitization(event, result);
    return { result, sanitizedEvent };
  }

  private async scanField(
    content: string,
    context: ScanContext,
  ): Promise<FieldScanResult> {
    const allDetections: Detection[] = [];

    for (const tier of this.tiers) {
      const detections = await tier.analyze(content, context);
      allDetections.push(...detections);
    }

    const { score, level, action } = this.scorer.scoreField(allDetections);

    const fieldResult: FieldScanResult = {
      fieldName: context.fieldName,
      originalLength: content.length,
      riskScore: score,
      riskLevel: level,
      action,
      detections: allDetections.slice(0, SECURITY_LIMITS.maxDetectionsPerField),
    };

    if (action === SecurityAction.REDACT || action === SecurityAction.BLOCK) {
      fieldResult.sanitizedContent = this.redactor.redact(content, fieldResult);
    }

    return fieldResult;
  }

  private applySanitization(
    event: CalendarEvent,
    result: EventScanResult,
  ): CalendarEvent {
    if (result.overallAction === SecurityAction.PASS) {
      return event;
    }

    const sanitized = { ...event };

    for (const fieldResult of result.fieldResults) {
      if (
        fieldResult.sanitizedContent !== undefined &&
        (fieldResult.action === SecurityAction.REDACT ||
          fieldResult.action === SecurityAction.BLOCK)
      ) {
        switch (fieldResult.fieldName) {
          case 'summary':
            sanitized.summary = fieldResult.sanitizedContent;
            break;
          case 'description':
            sanitized.description = fieldResult.sanitizedContent;
            break;
          case 'location':
            sanitized.location = fieldResult.sanitizedContent;
            break;
        }
      }
    }

    return sanitized;
  }

  private extractScannableFields(event: CalendarEvent): Array<{
    fieldName: string;
    fieldType: ScanContext['fieldType'];
    content: string;
  }> {
    const fields: Array<{
      fieldName: string;
      fieldType: ScanContext['fieldType'];
      content: string;
    }> = [];

    if (event.summary) {
      fields.push({ fieldName: 'summary', fieldType: 'title', content: event.summary });
    }
    if (event.description) {
      fields.push({ fieldName: 'description', fieldType: 'description', content: event.description });
    }
    if (event.location) {
      fields.push({ fieldName: 'location', fieldType: 'location', content: event.location });
    }
    if (event.attendees) {
      for (let i = 0; i < event.attendees.length; i++) {
        const attendee = event.attendees[i];
        if (attendee.displayName) {
          fields.push({
            fieldName: `attendees[${i}].displayName`,
            fieldType: 'attendee_name',
            content: attendee.displayName,
          });
        }
      }
    }
    if (event.attachments) {
      for (let i = 0; i < event.attachments.length; i++) {
        const attachment = event.attachments[i];
        if (attachment.title) {
          fields.push({
            fieldName: `attachments[${i}].title`,
            fieldType: 'attachment',
            content: attachment.title,
          });
        }
      }
    }
    return fields;
  }

  private extractDomain(email?: string): string | undefined {
    if (!email) return undefined;
    const parts = email.split('@');
    return parts.length === 2 ? parts[1].toLowerCase() : undefined;
  }
}
