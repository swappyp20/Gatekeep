import type { Env } from '../index.js';
import { FingerprintStore } from '../store/fingerprint-store.js';

/**
 * GET /api/v1/check/:hash
 *
 * Check if a SHA-256 hash is a known threat.
 * Returns threat metadata if found, or a negative result.
 */
export async function handleCheck(hash: string, env: Env): Promise<Response> {
  // Validate hash format
  const hashPattern = /^[a-f0-9]{64}$/;
  if (!hashPattern.test(hash)) {
    return jsonResponse({ error: 'Invalid hash format (expected SHA-256 hex)' }, 400);
  }

  const store = new FingerprintStore(env);
  const entry = await store.check(hash);

  if (!entry) {
    return jsonResponse({
      known: false,
      confidence: 0,
      reportCount: 0,
    });
  }

  return jsonResponse({
    known: true,
    confidence: entry.confidence,
    reportCount: entry.reportCount,
    firstSeen: entry.firstSeen,
    lastSeen: entry.lastSeen,
    category: entry.category,
  });
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
