import { SanitizationEngine, type CalendarEvent } from '../security/engine.js';
import { SecurityAnnotator } from '../security/actions/annotator.js';
import { AuditLogger } from '../reporting/audit-logger.js';
import { QuarantineStore } from '../security/actions/quarantine.js';
import type { EventScanResult } from '../security/types.js';
import { RiskLevel, SecurityAction } from '../security/types.js';

type ToolResult = { content: Array<{ type: 'text'; text: string }> };

/**
 * Names of upstream handlers whose results contain event data that must be scanned.
 */
const SCANNABLE_TOOLS = new Set([
  'list-events',
  'search-events',
  'get-event',
  'create-event',
  'update-event',
]);

/**
 * Intercepts MCP tool responses from the upstream google-calendar-mcp
 * to run all event data through the Gatekeep sanitization engine.
 */
export class ProxyHandler {
  private engine: SanitizationEngine;
  private annotator: SecurityAnnotator;
  private auditLogger: AuditLogger;
  private quarantineStore: QuarantineStore;

  constructor(engine: SanitizationEngine) {
    this.engine = engine;
    this.annotator = new SecurityAnnotator();
    this.auditLogger = new AuditLogger();
    this.quarantineStore = new QuarantineStore();
  }

  /** Get the quarantine store instance for use by MCP tools. */
  getQuarantineStore(): QuarantineStore {
    return this.quarantineStore;
  }

  /**
   * Wrap the upstream executeWithHandler to inject security scanning.
   *
   * Usage in server.ts:
   *   const proxied = proxyHandler.createProxiedExecutor(
   *     this.executeWithHandler.bind(this)
   *   );
   *   ToolRegistry.registerAll(this.server, proxied, this.config);
   */
  createProxiedExecutor(
    originalExecutor: (handler: any, args: any) => Promise<ToolResult>,
  ): (handler: any, args: any) => Promise<ToolResult> {
    return async (handler: any, args: any): Promise<ToolResult> => {
      const result = await originalExecutor(handler, args);

      // Determine tool name from handler class name
      const handlerName = handler.constructor?.name ?? '';
      const toolName = this.handlerToToolName(handlerName);

      if (!toolName || !SCANNABLE_TOOLS.has(toolName)) {
        return result;
      }

      // Extract text content from the MCP response
      const responseText =
        result.content?.[0]?.type === 'text' ? result.content[0].text : null;
      if (!responseText) return result;

      // Try to extract events from response text
      const events = this.extractEventsFromResponse(responseText);
      if (events.length === 0) return result;

      // Scan all events
      const scanResults: Array<{
        result: EventScanResult;
        sanitizedEvent: CalendarEvent;
      }> = [];

      for (const event of events) {
        const scanResult = await this.engine.scanEvent(event);
        scanResults.push(scanResult);
      }

      // Audit log all scan results (fire-and-forget)
      this.auditLogger.logBatch(scanResults.map(r => r.result)).catch(() => {});

      // Quarantine original content for blocked/redacted events (fire-and-forget)
      for (const { result: scanResult } of scanResults) {
        if (
          scanResult.overallAction === SecurityAction.BLOCK ||
          scanResult.overallAction === SecurityAction.REDACT
        ) {
          const originalEvent = events.find(e => e.id === scanResult.eventId);
          if (originalEvent) {
            const originalFields: Record<string, string> = {};
            if (originalEvent.summary) originalFields.summary = originalEvent.summary;
            if (originalEvent.description) originalFields.description = originalEvent.description;
            if (originalEvent.location) originalFields.location = originalEvent.location;
            this.quarantineStore.store(scanResult, originalFields).catch(() => {});
          }
        }
      }

      // Check if any events were flagged
      const anyFlagged = scanResults.some(
        r => r.result.overallRiskLevel !== RiskLevel.SAFE,
      );

      if (!anyFlagged) {
        return result;
      }

      // Build annotations
      const annotations = this.annotator.buildAnnotations(
        scanResults.map(r => r.result),
      );

      // Replace event data in the original response with sanitized versions
      let sanitizedResponseText = responseText;
      for (const { result: scanResult, sanitizedEvent } of scanResults) {
        if (scanResult.overallRiskLevel !== RiskLevel.SAFE) {
          // Replace the original event data with sanitized version
          sanitizedResponseText = this.replaceEventInResponse(
            sanitizedResponseText,
            scanResult.eventId,
            sanitizedEvent,
          );
        }
      }

      const annotatedText = annotations
        ? `${annotations}\n\n---\n\n${sanitizedResponseText}`
        : sanitizedResponseText;

      return {
        content: [{ type: 'text' as const, text: annotatedText }],
      };
    };
  }

  /**
   * Map handler class names to tool names for SCANNABLE_TOOLS lookup.
   */
  private handlerToToolName(handlerName: string): string | null {
    const mapping: Record<string, string> = {
      ListEventsHandler: 'list-events',
      SearchEventsHandler: 'search-events',
      GetEventHandler: 'get-event',
      CreateEventHandler: 'create-event',
      UpdateEventHandler: 'update-event',
    };
    return mapping[handlerName] ?? null;
  }

  /**
   * Extract calendar events from the raw MCP response text.
   * The upstream handlers return structured text; we look for JSON event data.
   */
  private extractEventsFromResponse(responseText: string): CalendarEvent[] {
    try {
      const parsed = JSON.parse(responseText);

      // Handle array of events (list-events, search-events)
      if (Array.isArray(parsed)) {
        return parsed
          .filter((item: any) => item && typeof item === 'object' && item.id)
          .map((item: any) => this.normalizeEvent(item));
      }

      // Handle single event (get-event, create-event, update-event)
      if (parsed && typeof parsed === 'object' && parsed.id) {
        return [this.normalizeEvent(parsed)];
      }

      // Handle response wrapper with events array
      if (parsed?.events && Array.isArray(parsed.events)) {
        return parsed.events
          .filter((item: any) => item && typeof item === 'object' && item.id)
          .map((item: any) => this.normalizeEvent(item));
      }

      return [];
    } catch {
      // Not JSON; try to find event-like structures in plain text
      return this.extractEventsFromPlainText(responseText);
    }
  }

  /**
   * Attempt to extract events from structured but non-JSON text responses.
   */
  private extractEventsFromPlainText(text: string): CalendarEvent[] {
    // The upstream handlers format responses as structured text.
    // Extract fields by looking for common patterns.
    const events: CalendarEvent[] = [];
    const eventBlocks = text.split(/(?=Event ID:|---)/);

    for (const block of eventBlocks) {
      const idMatch = block.match(/Event ID:\s*(.+)/);
      if (!idMatch) continue;

      const summaryMatch = block.match(/(?:Summary|Title):\s*(.+)/);
      const descMatch = block.match(/Description:\s*([\s\S]*?)(?=\n\w+:|$)/);
      const locMatch = block.match(/Location:\s*(.+)/);
      const orgMatch = block.match(/Organizer:\s*(.+)/);

      events.push({
        id: idMatch[1].trim(),
        summary: summaryMatch?.[1]?.trim(),
        description: descMatch?.[1]?.trim(),
        location: locMatch?.[1]?.trim(),
        organizer: orgMatch
          ? { email: orgMatch[1].trim() }
          : undefined,
      });
    }

    return events;
  }

  private normalizeEvent(raw: any): CalendarEvent {
    return {
      id: raw.id ?? 'unknown',
      calendarId: raw.calendarId,
      summary: raw.summary,
      description: raw.description,
      location: raw.location,
      organizer: raw.organizer,
      attendees: raw.attendees,
      attachments: raw.attachments,
    };
  }

  /**
   * Replace an event's data in the response with the sanitized version.
   */
  private replaceEventInResponse(
    responseText: string,
    eventId: string,
    sanitizedEvent: CalendarEvent,
  ): string {
    try {
      const parsed = JSON.parse(responseText);

      if (Array.isArray(parsed)) {
        const idx = parsed.findIndex((e: any) => e?.id === eventId);
        if (idx >= 0) {
          parsed[idx] = { ...parsed[idx], ...sanitizedEvent };
        }
        return JSON.stringify(parsed);
      }

      if (parsed?.id === eventId) {
        return JSON.stringify({ ...parsed, ...sanitizedEvent });
      }

      if (parsed?.events && Array.isArray(parsed.events)) {
        const idx = parsed.events.findIndex((e: any) => e?.id === eventId);
        if (idx >= 0) {
          parsed.events[idx] = { ...parsed.events[idx], ...sanitizedEvent };
        }
        return JSON.stringify(parsed);
      }

      return responseText;
    } catch {
      // Non-JSON response — return as-is with annotations handled upstream
      return responseText;
    }
  }
}
