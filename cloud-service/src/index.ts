/**
 * CalGuard Cloud Threat Intelligence API
 *
 * Cloudflare Worker that serves as a community-fed threat database
 * for CalGuard instances. Only processes SHA-256 fingerprints —
 * never raw calendar content.
 *
 * Endpoints:
 *   POST /api/v1/report     — Submit a threat fingerprint
 *   GET  /api/v1/check/:hash — Check if a hash is a known threat
 *   GET  /api/v1/feed        — Pull recent threat hashes
 */

import { handleReport } from './routes/report.js';
import { handleCheck } from './routes/check.js';
import { handleFeed } from './routes/feed.js';

export interface Env {
  THREAT_STORE: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      let response: Response;

      if (request.method === 'POST' && path === '/api/v1/report') {
        response = await handleReport(request, env);
      } else if (request.method === 'GET' && path.startsWith('/api/v1/check/')) {
        const hash = path.replace('/api/v1/check/', '');
        response = await handleCheck(hash, env);
      } else if (request.method === 'GET' && path === '/api/v1/feed') {
        const since = url.searchParams.get('since');
        response = await handleFeed(since, env);
      } else if (path === '/health') {
        response = new Response(JSON.stringify({ status: 'ok' }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } else {
        response = new Response(
          JSON.stringify({ error: 'Not found' }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        );
      }

      // Add CORS headers to response
      for (const [key, value] of Object.entries(corsHeaders)) {
        response.headers.set(key, value);
      }

      return response;
    } catch (err) {
      return new Response(
        JSON.stringify({ error: 'Internal server error' }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        },
      );
    }
  },
};
