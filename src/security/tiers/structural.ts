import type { DetectionTier } from './base-tier.js';
import type { Detection, ScanContext } from '../types.js';
import { SECURITY_LIMITS } from '../types.js';

/**
 * Tier 1: Structural Analysis
 * Detects technical attack markers that should rarely appear in legitimate calendar events.
 */
export class StructuralAnalyzer implements DetectionTier {
  readonly tierName = 'structural';

  analyze(text: string, _context: ScanContext): Detection[] {
    if (!text || text.length === 0) return [];

    // Truncate to limit to prevent DoS
    const truncated = text.length > SECURITY_LIMITS.maxFieldLength
      ? text.slice(0, SECURITY_LIMITS.maxFieldLength)
      : text;

    const detections: Detection[] = [];

    detections.push(...this.detectZeroWidthChars(truncated));
    detections.push(...this.detectBase64Payloads(truncated));
    detections.push(...this.detectHtmlInjection(truncated));
    detections.push(...this.detectJavascriptUris(truncated));
    detections.push(...this.detectMarkdownExploits(truncated));
    detections.push(...this.detectUnicodeHomoglyphs(truncated));
    detections.push(...this.detectExcessiveEncoding(truncated));
    detections.push(...this.detectDataUris(truncated));
    detections.push(...this.detectHiddenText(truncated));

    // Enforce max detections per field
    return detections.slice(0, SECURITY_LIMITS.maxDetectionsPerField);
  }

  /**
   * STRUCT-001: Zero-Width Characters
   * Detects invisible Unicode characters used to hide text from human view
   * while remaining visible to LLMs.
   */
  private detectZeroWidthChars(text: string): Detection[] {
    const detections: Detection[] = [];
    // U+200B Zero Width Space, U+200C ZWNJ, U+200D ZWJ,
    // U+FEFF BOM/ZWNBS, U+2060 Word Joiner, U+180E Mongolian Vowel Sep
    const pattern = /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/g;
    let match: RegExpExecArray | null;
    let count = 0;

    while ((match = pattern.exec(text)) !== null) {
      count++;
    }

    if (count > 0) {
      detections.push({
        tier: 'structural',
        ruleId: 'STRUCT-001',
        ruleName: 'Zero-Width Characters',
        severity: count >= 5 ? 0.8 : 0.7,
        matchedContent: `${count} zero-width character(s) found`,
        matchOffset: 0,
        matchLength: 0,
        confidence: 0.9,
        metadata: { count },
      });
    }
    return detections;
  }

  /**
   * STRUCT-002: Base64 Payloads
   * Detects base64-encoded blocks that may contain hidden instructions.
   */
  private detectBase64Payloads(text: string): Detection[] {
    const detections: Detection[] = [];
    // Match base64 blocks of 32+ chars (short blocks are common in URLs, etc.)
    const pattern = /[A-Za-z0-9+/]{32,}={0,2}/g;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(text)) !== null) {
      const encoded = match[0];
      let decoded: string | null = null;
      try {
        decoded = Buffer.from(encoded, 'base64').toString('utf-8');
      } catch {
        continue;
      }

      if (!decoded) continue;

      // Check if decoded content looks suspicious (shell commands, scripts, etc.)
      const suspiciousPatterns = [
        /\b(bash|sh|curl|wget|chmod|rm\s|python|node|exec|eval|powershell)\b/i,
        /\b(ignore|override|system|instruction|prompt)\b/i,
        /<script/i,
        /\|\s*(bash|sh)\b/i,
      ];

      const isSuspicious = suspiciousPatterns.some(p => p.test(decoded!));

      if (isSuspicious) {
        detections.push({
          tier: 'structural',
          ruleId: 'STRUCT-002',
          ruleName: 'Base64 Payload',
          severity: 0.8,
          matchedContent: encoded.slice(0, 60) + (encoded.length > 60 ? '...' : ''),
          matchOffset: match.index,
          matchLength: encoded.length,
          confidence: 0.85,
          metadata: { decodedPreview: decoded.slice(0, 100) },
        });
      }
    }
    return detections;
  }

  /**
   * STRUCT-003: HTML/Script Injection
   * Detects dangerous HTML tags and event handler attributes.
   */
  private detectHtmlInjection(text: string): Detection[] {
    const detections: Detection[] = [];

    const dangerousTags = /<\s*(script|iframe|object|embed|form|input|svg|link|meta|base)\b[^>]*>/gi;
    let match: RegExpExecArray | null;

    while ((match = dangerousTags.exec(text)) !== null) {
      detections.push({
        tier: 'structural',
        ruleId: 'STRUCT-003',
        ruleName: 'HTML/Script Injection',
        severity: 0.9,
        matchedContent: match[0].slice(0, 80),
        matchOffset: match.index,
        matchLength: match[0].length,
        confidence: 0.95,
      });
    }

    // Check for event handler attributes (onerror, onload, onclick, etc.)
    const eventHandlers = /\bon\w+\s*=\s*["'][^"']*["']/gi;
    while ((match = eventHandlers.exec(text)) !== null) {
      detections.push({
        tier: 'structural',
        ruleId: 'STRUCT-003',
        ruleName: 'HTML Event Handler',
        severity: 0.85,
        matchedContent: match[0].slice(0, 80),
        matchOffset: match.index,
        matchLength: match[0].length,
        confidence: 0.9,
      });
    }

    return detections;
  }

  /**
   * STRUCT-004: JavaScript URIs
   * Detects javascript:, vbscript:, and similar dangerous URI schemes.
   * Whitespace-tolerant to catch obfuscation.
   */
  private detectJavascriptUris(text: string): Detection[] {
    const detections: Detection[] = [];

    // Whitespace-tolerant patterns for JS URI schemes
    const patterns = [
      /j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:/gi,
      /v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:/gi,
    ];

    for (const pattern of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'structural',
          ruleId: 'STRUCT-004',
          ruleName: 'JavaScript URI',
          severity: 0.95,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.95,
        });
      }
    }

    return detections;
  }

  /**
   * STRUCT-005: Markdown Link Obfuscation
   * Detects markdown links where the URL contains suspicious patterns
   * (command injection, IP addresses, suspicious domains).
   */
  private detectMarkdownExploits(text: string): Detection[] {
    const detections: Detection[] = [];
    const markdownLink = /\[([^\]]*)\]\(([^)]+)\)/g;
    let match: RegExpExecArray | null;

    while ((match = markdownLink.exec(text)) !== null) {
      const url = match[2];
      const suspiciousUrl =
        /javascript:/i.test(url) ||
        /data:/i.test(url) ||
        /\|\s*(bash|sh)/i.test(url) ||
        /[;&|`$]/.test(url) ||
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);

      if (suspiciousUrl) {
        detections.push({
          tier: 'structural',
          ruleId: 'STRUCT-005',
          ruleName: 'Markdown Link Obfuscation',
          severity: /javascript:|data:/i.test(url) ? 0.85 : 0.6,
          matchedContent: match[0].slice(0, 100),
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.8,
        });
      }
    }

    return detections;
  }

  /**
   * STRUCT-006: Unicode Homoglyphs
   * Detects mixed-script characters that substitute Latin characters
   * to bypass keyword-based detection.
   */
  private detectUnicodeHomoglyphs(text: string): Detection[] {
    const detections: Detection[] = [];

    // Common Cyrillic/Greek homoglyphs of Latin chars: а(a), е(e), о(o), р(p), с(c), у(y), х(x)
    // Cyrillic range: \u0400-\u04FF, Greek: \u0370-\u03FF
    const hasCyrillic = /[\u0400-\u04FF]/.test(text);
    const hasGreek = /[\u0370-\u03FF]/.test(text);
    const hasLatin = /[a-zA-Z]/.test(text);

    // Mixed-script detection: Latin + Cyrillic or Latin + Greek in same field
    if (hasLatin && (hasCyrillic || hasGreek)) {
      // Look for words that mix scripts (strong signal of homoglyph attack)
      const words = text.split(/\s+/);
      let mixedWords = 0;
      for (const word of words) {
        const wordHasLatin = /[a-zA-Z]/.test(word);
        const wordHasCyrillic = /[\u0400-\u04FF]/.test(word);
        const wordHasGreek = /[\u0370-\u03FF]/.test(word);
        if (wordHasLatin && (wordHasCyrillic || wordHasGreek)) {
          mixedWords++;
        }
      }

      if (mixedWords > 0) {
        detections.push({
          tier: 'structural',
          ruleId: 'STRUCT-006',
          ruleName: 'Unicode Homoglyphs',
          severity: mixedWords >= 5 ? 0.85 : mixedWords >= 3 ? 0.75 : 0.5,
          matchedContent: `${mixedWords} word(s) with mixed Unicode scripts`,
          matchOffset: 0,
          matchLength: 0,
          confidence: 0.75,
          metadata: { mixedWords },
        });
      }
    }

    return detections;
  }

  /**
   * STRUCT-007: Excessive Encoding
   * Detects double/triple URL encoding, nested base64, or HTML entity chains.
   */
  private detectExcessiveEncoding(text: string): Detection[] {
    const detections: Detection[] = [];

    // Double URL encoding: %25XX patterns (% encoded as %25)
    const doubleUrlEncoding = /%25[0-9A-Fa-f]{2}/g;
    const doubleEncodeMatches = text.match(doubleUrlEncoding);
    if (doubleEncodeMatches && doubleEncodeMatches.length >= 3) {
      detections.push({
        tier: 'structural',
        ruleId: 'STRUCT-007',
        ruleName: 'Double URL Encoding',
        severity: 0.80,
        matchedContent: `${doubleEncodeMatches.length} double-encoded sequences`,
        matchOffset: 0,
        matchLength: 0,
        confidence: 0.8,
        metadata: { count: doubleEncodeMatches.length },
      });
    }

    // Excessive HTML entities (>10 in a block suggests obfuscation)
    const htmlEntities = /&(?:#\d{2,4}|#x[0-9a-fA-F]{2,4}|[a-zA-Z]+);/g;
    const entityMatches = text.match(htmlEntities);
    if (entityMatches && entityMatches.length >= 10) {
      detections.push({
        tier: 'structural',
        ruleId: 'STRUCT-007',
        ruleName: 'Excessive HTML Entities',
        severity: 0.80,
        matchedContent: `${entityMatches.length} HTML entities`,
        matchOffset: 0,
        matchLength: 0,
        confidence: 0.7,
        metadata: { count: entityMatches.length },
      });
    }

    return detections;
  }

  /**
   * STRUCT-008: Data URIs
   * Detects data: URIs that could embed executable content.
   */
  private detectDataUris(text: string): Detection[] {
    const detections: Detection[] = [];
    const pattern = /data:\s*[^;]+;\s*base64\s*,/gi;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(text)) !== null) {
      detections.push({
        tier: 'structural',
        ruleId: 'STRUCT-008',
        ruleName: 'Data URI',
        severity: 0.85,
        matchedContent: match[0],
        matchOffset: match.index,
        matchLength: match[0].length,
        confidence: 0.9,
      });
    }

    return detections;
  }

  /**
   * STRUCT-009: Hidden Text (CSS/HTML)
   * Detects content hidden via CSS tricks: display:none, font-size:0, etc.
   */
  private detectHiddenText(text: string): Detection[] {
    const detections: Detection[] = [];
    const patterns = [
      /display\s*:\s*none/gi,
      /font-size\s*:\s*0/gi,
      /opacity\s*:\s*0(?![.])/gi,
      /visibility\s*:\s*hidden/gi,
      /color\s*:\s*(?:#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*;?\s*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))/gi,
      /height\s*:\s*0[^0-9]/gi,
      /overflow\s*:\s*hidden/gi,
    ];

    for (const pattern of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'structural',
          ruleId: 'STRUCT-009',
          ruleName: 'Hidden Text (CSS)',
          severity: 0.75,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.8,
        });
      }
    }

    return detections;
  }
}
