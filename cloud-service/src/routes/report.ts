import type { Env } from '../index.js';
import { FingerprintStore } from '../store/fingerprint-store.js';

/** Schema for the report request body. */
interface ReportRequest {
  clientId: string;
  fingerprint: {
    contentHash: string;
    structuralHash: string;
    patternIds: string[];
    riskScore: number;
    organizerDomain?: string;
  };
  reportedAt: string;
}

/**
 * POST /api/v1/report
 *
 * Submit a threat fingerprint report.
 * Validates input, records both content and structural hashes.
 */
export async function handleReport(request: Request, env: Env): Promise<Response> {
  let body: ReportRequest;

  try {
    body = await request.json() as ReportRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  // Validate required fields
  if (!body.clientId || typeof body.clientId !== 'string') {
    return jsonResponse({ error: 'Missing or invalid clientId' }, 400);
  }
  if (!body.fingerprint?.contentHash || !body.fingerprint?.structuralHash) {
    return jsonResponse({ error: 'Missing fingerprint hashes' }, 400);
  }
  if (typeof body.fingerprint.riskScore !== 'number' || body.fingerprint.riskScore < 0 || body.fingerprint.riskScore > 1) {
    return jsonResponse({ error: 'Invalid riskScore (must be 0.0 - 1.0)' }, 400);
  }

  // Validate hash format (SHA-256 hex string)
  const hashPattern = /^[a-f0-9]{64}$/;
  if (!hashPattern.test(body.fingerprint.contentHash) || !hashPattern.test(body.fingerprint.structuralHash)) {
    return jsonResponse({ error: 'Invalid hash format (expected SHA-256 hex)' }, 400);
  }

  const store = new FingerprintStore(env);

  // Record both hashes
  const contentResult = await store.recordReport(
    body.fingerprint.contentHash,
    body.fingerprint.patternIds ?? [],
    body.fingerprint.riskScore,
    body.fingerprint.organizerDomain,
  );

  await store.recordReport(
    body.fingerprint.structuralHash,
    body.fingerprint.patternIds ?? [],
    body.fingerprint.riskScore,
    body.fingerprint.organizerDomain,
  );

  return jsonResponse({
    accepted: true,
    contentHash: {
      reportCount: contentResult.reportCount,
      confidence: contentResult.confidence,
    },
  }, 201);
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
