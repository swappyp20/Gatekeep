import type { Env } from '../index.js';
import { FingerprintStore } from '../store/fingerprint-store.js';

/**
 * GET /api/v1/feed?since=<ISO8601>
 *
 * Pull recent high-confidence threat hashes for local cache sync.
 * Returns entries added/updated after the `since` timestamp.
 */
export async function handleFeed(since: string | null, env: Env): Promise<Response> {
  // Validate since parameter if provided
  if (since) {
    const parsed = Date.parse(since);
    if (isNaN(parsed)) {
      return jsonResponse({ error: 'Invalid since parameter (expected ISO 8601 timestamp)' }, 400);
    }
  }

  const store = new FingerprintStore(env);
  const threats = await store.getFeedSince(since);

  const entries = threats.map(t => ({
    hash: t.hash,
    hashType: t.hashType,
    confidence: t.confidence,
    reportCount: t.reportCount,
    updatedAt: t.lastSeen,
    category: t.category,
  }));

  return jsonResponse({
    entries,
    count: entries.length,
    syncedAt: new Date().toISOString(),
  });
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
