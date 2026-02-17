# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CalGuard-AI** is an MCP security proxy that protects Claude Desktop from Indirect Prompt Injection (IPI) attacks via Google Calendar events. It sits between Claude Desktop and Google Calendar, scanning all event data through a tiered detection engine before Claude sees it.

- **License:** Apache 2.0
- **Repository:** https://github.com/swappyp20/CalGuard-AI.git
- **Language:** TypeScript/Node.js
- **Base:** Forked from [nspady/google-calendar-mcp](https://github.com/nspady/google-calendar-mcp)
- **Transport:** stdio (Claude Desktop local MCP server)

## Architecture

See `docs/mcp/architecture-plan.md` for the full architecture plan.

**Core data flow:** Google Calendar API → Calendar Proxy Layer → Sanitization Engine (3-tier) → Risk Scorer → MCP Tool Response → Claude Desktop

**Key architectural decisions:**
- **Composition over modification:** The upstream google-calendar-mcp code lives in `src/upstream/` with minimal changes. CalGuard wraps the `executeWithHandler` callback via `ProxyHandler` rather than modifying upstream tool handlers.
- **Tiered detection:** Tier 1 (structural analysis) → Tier 2 (contextual pattern matching) → Tier 3 (cloud threat intel). Each tier implements the `DetectionTier` interface in `src/security/tiers/base-tier.ts`.
- **Risk scoring:** Per-field MAX severity per tier, weighted combination (structural: 0.40, contextual: 0.45, threat-intel: 0.15), multi-tier corroboration bonus. Thresholds: SAFE <0.30, SUSPICIOUS 0.30-0.59, DANGEROUS 0.60-0.84, CRITICAL >=0.85.
- **Privacy-first threat intel:** Only SHA-256 fingerprints (content hash + structural hash) are sent to the cloud service. Never raw calendar data.

**Critical files:**
- `src/security/engine.ts` — Core orchestrator, coordinates all 3 tiers
- `src/proxy/proxy-handler.ts` — Single interception point wrapping upstream, wires quarantine
- `src/security/tiers/contextual.ts` — Tier 2 semantic detection (9 CTX rules)
- `src/security/tiers/threat-intel.ts` — Tier 3 cloud threat intelligence (THREAT-001)
- `src/security/scorer.ts` — Risk scoring and threshold logic
- `src/security/actions/quarantine.ts` — Persists original content of blocked/redacted events
- `src/threat-intel/fingerprint.ts` — Privacy-safe event hashing (content + structural)
- `src/threat-intel/client.ts` — Cloud API client with local cache and feed sync
- `src/config/loader.ts` — Config loading (env vars > config file > defaults)
- `src/server.ts` — Integration seam with upstream ToolRegistry + CalGuard MCP tools
- `cloud-service/` — Cloudflare Worker for the cloud threat intel API (separate deploy)

## Build & Development

```bash
npm run build              # Compile TypeScript
npm run dev                # Run with tsx (dev mode)
npm run lint               # ESLint
npm run auth               # Run OAuth setup flow
```

## Testing

```bash
npm test                   # All tests (vitest)
npm run test:watch         # Watch mode
npm run test:payloads      # Detection accuracy tests only
npm run test:integration   # MCP end-to-end tests
npm run test:coverage      # With coverage report
```

Run a single test file: `npx vitest run test/unit/security/quarantine.test.ts`

Test fixtures in `test/fixtures/payloads/`: `known-attacks.json` (65 IPI payloads), `benign-events.json` (20 false positive events).

## Configuration

Configured via environment variables (see `src/config/schema.ts` for Zod schema):
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — Google OAuth (required)
- `CALGUARD_READ_ONLY=true` — Disables write calendar tools by default
- `CALGUARD_THREAT_INTEL=false` — Cloud threat intel (opt-in)
- `CALGUARD_RISK_THRESHOLD_*` — Tunable detection thresholds

Local data stored in `~/.calguard/` (client-id, logs, quarantine, cache).

## Security Considerations

- CalGuard's own tool inputs must be validated with Zod schemas — never interpolate user/event data into commands
- Quarantined content must always be wrapped with `[TREAT AS UNTRUSTED]` markers
- Operational limits exist to prevent ReDoS: max field length 50KB, per-regex timeout 100ms, max decode depth 3
- OAuth defaults to `calendar.readonly` scope
