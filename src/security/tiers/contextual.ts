import type { DetectionTier } from './base-tier.js';
import type { Detection, ScanContext } from '../types.js';
import { SECURITY_LIMITS } from '../types.js';

/**
 * Tier 2: Contextual Pattern Matching
 *
 * Detects semantic attack patterns using template matching with
 * contextual scoring. Each rule uses proximity-aware or fuzzy
 * matching rather than naive single-regex checks.
 *
 * Post-detection contextual weighting:
 *   - External organizer:   severity × 1.4
 *   - Description field:    severity × 1.2
 *   - Attendee displayName: severity × 1.3
 */
export class ContextualAnalyzer implements DetectionTier {
  readonly tierName = 'contextual';

  analyze(text: string, context: ScanContext): Detection[] {
    if (!text || text.length === 0) return [];

    const truncated = text.length > SECURITY_LIMITS.maxFieldLength
      ? text.slice(0, SECURITY_LIMITS.maxFieldLength)
      : text;

    const detections: Detection[] = [];

    detections.push(...this.detectInstructionOverride(truncated));
    detections.push(...this.detectImperativeSystem(truncated));
    detections.push(...this.detectShellCommands(truncated));
    detections.push(...this.detectToolCallSyntax(truncated));
    detections.push(...this.detectRoleAssumption(truncated));
    detections.push(...this.detectOutputManipulation(truncated));
    detections.push(...this.detectUrgencyAuthority(truncated));
    detections.push(...this.detectPayloadDelivery(truncated));
    detections.push(...this.detectSensitiveFilePaths(truncated));

    // Apply contextual weighting based on field type and organizer
    this.applyContextualWeighting(detections, context);

    return detections.slice(0, SECURITY_LIMITS.maxDetectionsPerField);
  }

  // ---------------------------------------------------------------------------
  // CTX-001: Instruction Override
  // Fuzzy match: {verb} ... {noun}
  //   verbs: ignore, disregard, forget, override, bypass, skip, discard, dismiss
  //   nouns: instructions, prompt, rules, commands, guidelines, constraints,
  //          directives, policies, restrictions, safeguards, system prompt
  // ---------------------------------------------------------------------------
  private detectInstructionOverride(text: string): Detection[] {
    const detections: Detection[] = [];
    const normalized = text.toLowerCase();

    const verbs = [
      'ignore', 'disregard', 'forget', 'override', 'bypass',
      'skip', 'discard', 'dismiss', 'abandon', 'drop',
    ];
    const modifiers = [
      'all', 'any', 'every', 'the', 'your', 'previous', 'prior',
      'above', 'existing', 'current', 'original', 'initial', 'old',
    ];
    const nouns = [
      'instructions', 'instruction', 'prompt', 'rules', 'commands',
      'guidelines', 'constraints', 'directives', 'policies', 'restrictions',
      'safeguards', 'safety', 'system prompt', 'programming', 'training',
      'context', 'protocols',
    ];

    // Build patterns: verb + (optional modifier) + noun within a sliding window
    for (const verb of verbs) {
      const verbIdx = normalized.indexOf(verb);
      if (verbIdx === -1) continue;

      // Look for a noun within 60 characters after the verb
      const window = normalized.slice(verbIdx, verbIdx + verb.length + 60);

      for (const noun of nouns) {
        if (window.includes(noun)) {
          // Compute a confidence boost if a modifier is also present
          const hasModifier = modifiers.some(m => window.includes(m));
          const matchStr = text.slice(verbIdx, Math.min(verbIdx + verb.length + 60, text.length)).trim();

          detections.push({
            tier: 'contextual',
            ruleId: 'CTX-001',
            ruleName: 'Instruction Override',
            severity: hasModifier ? 0.80 : 0.65,
            matchedContent: matchStr.slice(0, 100),
            matchOffset: verbIdx,
            matchLength: Math.min(matchStr.length, 100),
            confidence: hasModifier ? 0.90 : 0.75,
          });
          // Only report one match per verb occurrence
          break;
        }
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-002: Imperative + System
  // Imperative verb + system noun within 5 tokens
  //   verbs: execute, run, open, access, delete, read, write, create, send, call
  //   nouns: file, terminal, shell, command, system, API, code, server, database,
  //          directory, process, endpoint, registry, service, function
  // ---------------------------------------------------------------------------
  private detectImperativeSystem(text: string): Detection[] {
    const detections: Detection[] = [];

    const imperativeVerbs = [
      'execute', 'run', 'open', 'access', 'delete', 'read', 'write',
      'create', 'send', 'call', 'invoke', 'start', 'launch', 'spawn',
      'modify', 'remove', 'install', 'fetch', 'get', 'load',
    ];
    const systemNouns = [
      'file', 'files', 'terminal', 'shell', 'command', 'system', 'api',
      'code', 'server', 'database', 'directory', 'process', 'endpoint',
      'registry', 'service', 'function', 'script', 'binary', 'executable',
      'program', 'tool', 'plugin', 'module', 'contents',
    ];

    // Tokenize by whitespace/punctuation
    const tokens = text.toLowerCase().split(/[\s,.;:!?()\[\]{}"']+/).filter(Boolean);

    for (let i = 0; i < tokens.length; i++) {
      if (!imperativeVerbs.includes(tokens[i])) continue;

      // Search within the next 5 tokens
      const window = tokens.slice(i + 1, i + 6);
      const matchedNoun = window.find(t => systemNouns.includes(t));

      if (matchedNoun) {
        // Find the actual offset in the original text
        const verbOffset = this.findTokenOffset(text, tokens[i], i);
        const contextSnippet = tokens.slice(i, i + 6).join(' ');

        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-002',
          ruleName: 'Imperative + System',
          severity: 0.55,
          matchedContent: contextSnippet.slice(0, 80),
          matchOffset: verbOffset,
          matchLength: contextSnippet.length,
          confidence: 0.70,
          metadata: { verb: tokens[i], noun: matchedNoun },
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-003: Shell Commands
  // Shell syntax in non-code-block context: pipes, redirections,
  // curl|bash, rm -rf, chmod +x, powershell -enc, sudo, etc.
  // ---------------------------------------------------------------------------
  private detectShellCommands(text: string): Detection[] {
    const detections: Detection[] = [];

    // Strip fenced code blocks (```...```) — shell syntax in code blocks is benign
    const withoutCodeBlocks = text.replace(/```[\s\S]*?```/g, '');

    const shellPatterns: Array<{ pattern: RegExp; name: string; severity: number }> = [
      { pattern: /\bcurl\b[^|]*\|\s*(ba)?sh\b/gi, name: 'curl pipe shell', severity: 0.90 },
      { pattern: /\bwget\b[^|]*\|\s*(ba)?sh\b/gi, name: 'wget pipe shell', severity: 0.90 },
      { pattern: /\brm\s+-(r|f|rf|fr)\b/gi, name: 'rm -rf', severity: 0.85 },
      { pattern: /\bchmod\s+\+x\b/gi, name: 'chmod +x', severity: 0.70 },
      { pattern: /\bsudo\s+\w+/gi, name: 'sudo command', severity: 0.75 },
      { pattern: /\bpowershell\s+-(enc|encodedcommand|e|ep|nop|nologo|noprofile|windowstyle)\b/gi, name: 'PowerShell encoded', severity: 0.90 },
      { pattern: /\bpython\s+-c\s+['"]/gi, name: 'python -c', severity: 0.75 },
      { pattern: /\bnode\s+-e\s+['"]/gi, name: 'node -e', severity: 0.75 },
      { pattern: /\beval\s*\(/gi, name: 'eval()', severity: 0.80 },
      { pattern: />\s*\/etc\/(?:passwd|shadow|hosts)/gi, name: 'etc file redirect', severity: 0.90 },
      { pattern: /\b(?:nc|ncat|netcat)\s+-[lp]/gi, name: 'netcat listener', severity: 0.85 },
      { pattern: /\bbase64\s+(-d|--decode)\b/gi, name: 'base64 decode', severity: 0.70 },
      // Multi-step clone/install + execute chains
      { pattern: /\bgit\s+clone\b[^&;]*[&;]+[^&;]*\b(?:npm\s+(?:install|start|run)|node\s+|python\s+|\.\/)\b/gi, name: 'git clone + execute chain', severity: 0.85 },
      { pattern: /\bnpm\s+install\b[^&;]*[&;]+[^&;]*\b(?:npm\s+(?:start|run)|node\s+|npx\s+)\b/gi, name: 'npm install + execute chain', severity: 0.80 },
    ];

    for (const { pattern, name, severity } of shellPatterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(withoutCodeBlocks)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-003',
          ruleName: `Shell Command: ${name}`,
          severity,
          matchedContent: match[0].slice(0, 80),
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.85,
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-004: Tool Call Syntax
  // Patterns resembling MCP tool invocations: use_mcp_tool, <tool_call>,
  // JSON with "tool" + "arguments" keys, function_call, etc.
  // ---------------------------------------------------------------------------
  private detectToolCallSyntax(text: string): Detection[] {
    const detections: Detection[] = [];

    const toolPatterns: Array<{ pattern: RegExp; name: string; severity: number }> = [
      { pattern: /\buse_mcp_tool\b/gi, name: 'MCP tool invocation', severity: 0.90 },
      { pattern: /<tool_call>/gi, name: 'tool_call XML tag', severity: 0.85 },
      { pattern: /<\/tool_call>/gi, name: 'tool_call closing tag', severity: 0.85 },
      { pattern: /<function_call>/gi, name: 'function_call XML tag', severity: 0.85 },
      { pattern: /<tool_use>/gi, name: 'tool_use XML tag', severity: 0.85 },
      { pattern: /\bfunction_call\s*[:(]/gi, name: 'function_call syntax', severity: 0.80 },
      { pattern: /\btool_use\s*[:(]/gi, name: 'tool_use syntax', severity: 0.80 },
    ];

    for (const { pattern, name, severity } of toolPatterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-004',
          ruleName: `Tool Call Syntax: ${name}`,
          severity,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.90,
        });
      }
    }

    // Detect JSON-like structures with "tool" + "arguments" or "name" + "input" keys
    // that look like injected tool calls
    const jsonToolPattern = /\{\s*"(?:tool|function|name)"\s*:\s*"[^"]+"\s*,\s*"(?:arguments|input|parameters|params)"\s*:/gi;
    let jsonMatch: RegExpExecArray | null;
    while ((jsonMatch = jsonToolPattern.exec(text)) !== null) {
      detections.push({
        tier: 'contextual',
        ruleId: 'CTX-004',
        ruleName: 'Tool Call Syntax: JSON tool structure',
        severity: 0.80,
        matchedContent: jsonMatch[0].slice(0, 100),
        matchOffset: jsonMatch.index,
        matchLength: jsonMatch[0].length,
        confidence: 0.85,
      });
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-005: Role Assumption
  // "You are now", "Act as", "Your new role", "Enter developer mode",
  // "Pretend to be", "From now on you are", etc.
  // ---------------------------------------------------------------------------
  private detectRoleAssumption(text: string): Detection[] {
    const detections: Detection[] = [];

    const patterns: Array<{ pattern: RegExp; severity: number }> = [
      { pattern: /\byou\s+are\s+now\b/gi, severity: 0.70 },
      { pattern: /\bact\s+as\s+(a\s+|an\s+)?/gi, severity: 0.55 },
      { pattern: /\byour\s+new\s+role\b/gi, severity: 0.75 },
      { pattern: /\benter\s+(?:developer|admin|debug|root|sudo|god)\s+mode\b/gi, severity: 0.85 },
      { pattern: /\bpretend\s+(?:to\s+be|you\s+are)\b/gi, severity: 0.65 },
      { pattern: /\bfrom\s+now\s+on\s+you\s+are\b/gi, severity: 0.75 },
      { pattern: /\byou\s+(?:must|should|will)\s+now\s+(?:act|behave|respond|operate)\b/gi, severity: 0.70 },
      { pattern: /\bswitch\s+to\s+(?:\w+\s+)?mode\b/gi, severity: 0.60 },
      { pattern: /\byou\s+have\s+been\s+(?:upgraded|reprogrammed|updated|reconfigured)\b/gi, severity: 0.80 },
      { pattern: /\bforget\s+(?:that\s+)?you\s+are\b/gi, severity: 0.75 },
    ];

    for (const { pattern, severity } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-005',
          ruleName: 'Role Assumption',
          severity,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.80,
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-006: Output Manipulation
  // "Output only the raw", "Respond with just the code",
  // "Return only JSON containing", "Print only", etc.
  // ---------------------------------------------------------------------------
  private detectOutputManipulation(text: string): Detection[] {
    const detections: Detection[] = [];

    const patterns: Array<{ pattern: RegExp; severity: number }> = [
      { pattern: /\b(?:output|return|respond|reply|print|show|display)\s+(?:only|just|exclusively|solely)\b/gi, severity: 0.55 },
      { pattern: /\bdo\s+not\s+(?:include|add|show|display|mention)\s+(?:any\s+)?(?:warning|notice|annotation|safety|explanation|preamble)/gi, severity: 0.70 },
      { pattern: /\brespond\s+with\s+(?:only|just)\s+(?:the\s+)?(?:raw|plain|unfiltered|exact|original)\b/gi, severity: 0.65 },
      { pattern: /\bstrip\s+(?:all\s+)?(?:warning|safety|security|annotation)/gi, severity: 0.75 },
      { pattern: /\bdo\s+not\s+(?:filter|sanitize|redact|modify|censor)\b/gi, severity: 0.65 },
      { pattern: /\braw\s+(?:and\s+)?unfiltered\s+(?:output|response|data|content)\b/gi, severity: 0.60 },
    ];

    for (const { pattern, severity } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-006',
          ruleName: 'Output Manipulation',
          severity,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.75,
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-007: Urgency / Authority
  // "URGENT:", "CRITICAL SYSTEM UPDATE", "Admin override",
  // "This is your developer speaking", etc.
  // ---------------------------------------------------------------------------
  private detectUrgencyAuthority(text: string): Detection[] {
    const detections: Detection[] = [];

    const patterns: Array<{ pattern: RegExp; severity: number }> = [
      { pattern: /\b(?:URGENT|CRITICAL|EMERGENCY|IMMEDIATE)\s*(?::|!|-)\s*/g, severity: 0.55 },
      { pattern: /\b(?:critical|urgent)\s+system\s+(?:update|message|alert|notice|override)\b/gi, severity: 0.70 },
      { pattern: /\badmin(?:istrator)?\s+override\b/gi, severity: 0.75 },
      { pattern: /\bthis\s+is\s+(?:your|the)\s+(?:developer|administrator|admin|system|creator|owner)\b/gi, severity: 0.75 },
      { pattern: /\bauthorized\s+(?:by|from)\s+(?:the\s+)?(?:admin|developer|system|Anthropic|OpenAI)\b/gi, severity: 0.70 },
      { pattern: /\bsystem\s+(?:level\s+)?(?:override|command|directive)\b/gi, severity: 0.70 },
      { pattern: /\bpriority\s*:\s*(?:highest|critical|p0|urgent)\b/gi, severity: 0.50 },
      { pattern: /\b(?:do\s+this\s+)?immediately\s+(?:without|before)\s+(?:checking|verifying|asking|confirming)/gi, severity: 0.65 },
    ];

    for (const { pattern, severity } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-007',
          ruleName: 'Urgency / Authority',
          severity,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.75,
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // CTX-008: Payload Delivery
  // "Download from", "Fetch the script at", "curl this URL",
  // "pip install", "npm install -g", etc.
  // ---------------------------------------------------------------------------
  private detectPayloadDelivery(text: string): Detection[] {
    const detections: Detection[] = [];

    // Strip fenced code blocks
    const withoutCodeBlocks = text.replace(/```[\s\S]*?```/g, '');

    const patterns: Array<{ pattern: RegExp; name: string; severity: number }> = [
      { pattern: /\b(?:download|fetch|retrieve|grab|pull)\s+(?:the\s+)?(?:file|script|payload|binary|package|code)\s+(?:from|at)\b/gi, name: 'download instruction', severity: 0.75 },
      { pattern: /\bcurl\b[^;\n&]{0,80}https?:\/\//gi, name: 'curl URL', severity: 0.70 },
      { pattern: /\bwget\b[^;\n&]{0,80}https?:\/\//gi, name: 'wget URL', severity: 0.70 },
      { pattern: /\bpip\s+install\s+(?:--user\s+)?(?!-r\b)\S+/gi, name: 'pip install', severity: 0.60 },
      { pattern: /\bnpm\s+install\s+(?:-g\s+)\S+/gi, name: 'npm install -g', severity: 0.65 },
      { pattern: /\bnpm\s+install\s+(?!-[dD])\S+/gi, name: 'npm install package', severity: 0.55 },
      { pattern: /\bnpx\s+(?!-y\s+gatekeep)\S+/gi, name: 'npx execution', severity: 0.60 },
      { pattern: /\biex\s*\(\s*(?:new-object|invoke-webrequest|iwr)\b/gi, name: 'PowerShell IEX', severity: 0.90 },
      { pattern: /\bInvoke-(?:Expression|WebRequest|RestMethod)\b/gi, name: 'PowerShell Invoke', severity: 0.80 },
      { pattern: /\bimport\s+(?:os|subprocess|sys|shutil|ctypes)\b/gi, name: 'Python system import', severity: 0.65 },
      // Repository cloning
      { pattern: /\bgit\s+clone\s+\S+/gi, name: 'git clone', severity: 0.70 },
      // Package manager run/execute commands
      { pattern: /\bnpm\s+(?:run|start|exec)\s+\S+/gi, name: 'npm run/start', severity: 0.60 },
      { pattern: /\b(?:yarn|pnpm)\s+(?:run|start|exec|dlx)\s+\S+/gi, name: 'yarn/pnpm run', severity: 0.60 },
      // Other ecosystem installers
      { pattern: /\bgo\s+install\s+\S+/gi, name: 'go install', severity: 0.60 },
      { pattern: /\bcargo\s+install\s+\S+/gi, name: 'cargo install', severity: 0.60 },
      { pattern: /\bgem\s+install\s+\S+/gi, name: 'gem install', severity: 0.60 },
      { pattern: /\bcomposer\s+require\s+\S+/gi, name: 'composer require', severity: 0.60 },
      // Container execution
      { pattern: /\bdocker\s+(?:run|pull)\s+\S+/gi, name: 'docker run/pull', severity: 0.65 },
    ];

    for (const { pattern, name, severity } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(withoutCodeBlocks)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-008',
          ruleName: `Payload Delivery: ${name}`,
          severity,
          matchedContent: match[0].slice(0, 80),
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.80,
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // Sensitive File Paths
  // Detects references to credential files, SSH keys, shadow files, etc.
  // that should never appear in calendar events.
  // ---------------------------------------------------------------------------
  private detectSensitiveFilePaths(text: string): Detection[] {
    const detections: Detection[] = [];

    const patterns: Array<{ pattern: RegExp; name: string; severity: number }> = [
      { pattern: /~\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)\b/gi, name: 'SSH key path', severity: 0.75 },
      { pattern: /~\/\.aws\/(?:credentials|config)\b/gi, name: 'AWS credentials path', severity: 0.75 },
      { pattern: /~\/\.(?:env|netrc|pgpass|my\.cnf)\b/gi, name: 'credential file path', severity: 0.70 },
      { pattern: /\/etc\/(?:passwd|shadow|sudoers)\b/gi, name: 'system credential file', severity: 0.80 },
      { pattern: /~\/\.(?:bash_history|zsh_history)\b/gi, name: 'shell history path', severity: 0.65 },
      { pattern: /~\/\.gnupg\//gi, name: 'GPG keyring path', severity: 0.70 },
    ];

    for (const { pattern, name, severity } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        detections.push({
          tier: 'contextual',
          ruleId: 'CTX-009',
          ruleName: `Sensitive File Path: ${name}`,
          severity,
          matchedContent: match[0],
          matchOffset: match.index,
          matchLength: match[0].length,
          confidence: 0.85,
        });
      }
    }

    return detections;
  }

  // ---------------------------------------------------------------------------
  // Contextual Weighting
  // ---------------------------------------------------------------------------
  private applyContextualWeighting(detections: Detection[], context: ScanContext): void {
    for (const det of detections) {
      let multiplier = 1.0;

      // External organizer amplification
      if (context.isExternalOrganizer) {
        multiplier *= 1.4;
      }

      // Field-type weighting
      switch (context.fieldType) {
        case 'description':
          multiplier *= 1.2;
          break;
        case 'attendee_name':
          multiplier *= 1.3;
          break;
      }

      det.severity = Math.min(det.severity * multiplier, 1.0);
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Find the approximate character offset of the nth occurrence of a token.
   * Falls back to indexOf if not found at expected position.
   */
  private findTokenOffset(text: string, token: string, _tokenIndex: number): number {
    const lower = text.toLowerCase();
    const idx = lower.indexOf(token);
    return idx >= 0 ? idx : 0;
  }
}
