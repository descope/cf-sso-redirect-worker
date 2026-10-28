import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

// ── Constants ─────────────────────────────────────────────────────────────────
// vi.hoisted ensures these are available inside the vi.mock factory below,
// which is hoisted to run before any imports are evaluated.

const { HOSTNAME, CNAME, PROJECT_ID, IDP_TOKEN_HASH, ROTATED_TOKEN_HASH } = vi.hoisted(() => ({
  HOSTNAME: 'login.example.com',
  CNAME: 'auth.example.com',
  PROJECT_ID: 'TestProjectId123',
  // SHA-256 of 'Bearer idp-token' and 'Bearer rotated-idp-token'
  IDP_TOKEN_HASH: 'd2b8331133f778f455f6d4484ebdb2d6faf38b7dd3830b80d65aa0bb2f6e11cb',
  ROTATED_TOKEN_HASH: 'c15f21643c4ca164048153b39e7a9c3da6e31b9da133f8b844d26ba925314466',
}));

// ── Config mock ───────────────────────────────────────────────────────────────

vi.mock('../src/projectConfig.json', () => ({
  default: {
    [HOSTNAME]: {
      newCname: CNAME,
      projectId: PROJECT_ID,
      sso: { enabled: true, logOnly: false },
      scim: {
        enabled: true,
        logOnly: false,
        tenants: {
          con_test123: {
            tenantId: 'descope-tenant-abc',
            token: `Bearer ${PROJECT_ID}:scim-token-abc`,
            authHashes: [IDP_TOKEN_HASH, ROTATED_TOKEN_HASH],
          },
          con_nohash: {
            tenantId: 'descope-tenant-nohash',
            token: `Bearer ${PROJECT_ID}:scim-token-nohash`,
          },
        },
      },
    },
    'any-relaystate.example.com': {
      newCname: CNAME,
      projectId: PROJECT_ID,
      sso: { enabled: true, rewriteAnyRelayState: true },
      scim: { enabled: false },
    },
    'sso-disabled.example.com': {
      newCname: CNAME,
      projectId: PROJECT_ID,
      sso: { enabled: false },
      scim: { enabled: false },
    },
    'logonly.example.com': {
      newCname: CNAME,
      projectId: PROJECT_ID,
      sso: { enabled: true, logOnly: true, tenants: '*' },
      scim: { enabled: true, logOnly: true, tenants: '*' },
    },
    'scim-wildcard.example.com': {
      newCname: CNAME,
      projectId: PROJECT_ID,
      sso: { enabled: false },
      scim: { enabled: true, tenants: '*' },
    },
    'scim-logonly-tenants.example.com': {
      newCname: CNAME,
      projectId: PROJECT_ID,
      sso: { enabled: false },
      scim: {
        enabled: true,
        logOnly: true,
        tenants: {
          con_test123: {
            tenantId: 'descope-tenant-abc',
            token: `Bearer ${PROJECT_ID}:scim-token-abc`,
            authHashes: [IDP_TOKEN_HASH],
          },
        },
      },
    },
  },
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function samlPost(hostname: string, relayState?: string) {
  const body = new URLSearchParams({ SAMLResponse: 'base64encodedresponse' });
  if (relayState !== undefined) body.set('RelayState', relayState);
  return new IncomingRequest(`https://${hostname}/auth/saml/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
}

async function callWorker(request: Request<unknown, IncomingRequestCfProperties>) {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('SSO Redirect Worker', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── Pass-through sentinel (x-cf-no-redirect) ───────────────────────────────

  describe('pass-through sentinel', () => {
    it('pass-through paths attach the sentinel header', async () => {
      const req = new IncomingRequest('https://unknown.example.com/saml/callback');
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(called.headers.get('x-cf-no-redirect')).toBe('1');
    });

    it('re-entry with sentinel short-circuits: strips header and forwards without rewriting', async () => {
      // Simulate the sub-request the worker makes on re-entry: same SAML URL
      // that would normally be rewritten, but now carries the pass-through sentinel.
      const req = new IncomingRequest(`https://${HOSTNAME}/auth/saml/callback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'x-cf-no-redirect': '1',
        },
        body: new URLSearchParams({ SAMLResponse: 'base64', RelayState: 's/test' }).toString(),
      });
      await callWorker(req);
      expect(mockFetch).toHaveBeenCalledOnce();
      const called: Request = mockFetch.mock.calls[0][0];
      // URL is NOT rewritten to the Descope CNAME
      expect(new URL(called.url).hostname).toBe(HOSTNAME);
      // Sentinel is stripped so origin does not see it
      expect(called.headers.get('x-cf-no-redirect')).toBeNull();
    });
  });

  // ── Unknown hostname ────────────────────────────────────────────────────────

  describe('unknown hostname', () => {
    it('forwards the original request unchanged', async () => {
      const req = new IncomingRequest('https://unknown.example.com/saml/callback');
      await callWorker(req);
      expect(mockFetch).toHaveBeenCalledOnce();
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe('unknown.example.com');
    });
  });

  // ── SSO disabled ────────────────────────────────────────────────────────────

  describe('SSO disabled', () => {
    it('forwards SAML POST as-is', async () => {
      await callWorker(samlPost('sso-disabled.example.com', 's/test'));
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe('sso-disabled.example.com');
    });
  });

  // ── SP-initiated SAML ───────────────────────────────────────────────────────

  describe('SP-initiated SAML (POST with RelayState starting with s/)', () => {
    it('rewrites hostname, path, and projectId', async () => {
      await callWorker(samlPost(HOSTNAME, 's/somerequest'));
      const called: Request = mockFetch.mock.calls[0][0];
      const url = new URL(called.url);
      expect(url.hostname).toBe(CNAME);
      expect(url.pathname).toBe('/v1/auth/saml/acs');
      expect(url.searchParams.get('projectId')).toBe(PROJECT_ID);
    });
  });

  // ── IDP-initiated SAML ──────────────────────────────────────────────────────

  describe('IDP-initiated SAML (POST with no RelayState)', () => {
    it('rewrites hostname, path, and projectId', async () => {
      await callWorker(samlPost(HOSTNAME)); // no RelayState
      const called: Request = mockFetch.mock.calls[0][0];
      const url = new URL(called.url);
      expect(url.hostname).toBe(CNAME);
      expect(url.pathname).toBe('/v1/auth/saml/acs');
      expect(url.searchParams.get('projectId')).toBe(PROJECT_ID);
    });
  });

  // ── Non-Descope RelayState ──────────────────────────────────────────────────

  describe('SAML POST with non-Descope RelayState', () => {
    it('forwards the original request unchanged by default (gradual migration)', async () => {
      await callWorker(samlPost(HOSTNAME, 'some-other-value'));
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe(HOSTNAME);
    });

    it('rewrites to Descope ACS URL when rewriteAnyRelayState is enabled', async () => {
      await callWorker(samlPost('any-relaystate.example.com', 'some-other-value'));
      const called: Request = mockFetch.mock.calls[0][0];
      const url = new URL(called.url);
      expect(url.hostname).toBe(CNAME);
      expect(url.pathname).toBe('/v1/auth/saml/acs');
      expect(url.searchParams.get('projectId')).toBe(PROJECT_ID);
    });
  });

  // ── Form POST without SAMLResponse ──────────────────────────────────────────

  describe('form POST without SAMLResponse', () => {
    it('forwards the original request unchanged, even without RelayState', async () => {
      const req = new IncomingRequest(`https://${HOSTNAME}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: 'jdoe' }).toString(),
      });
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe(HOSTNAME);
      expect(called.headers.get('x-cf-no-redirect')).toBe('1');
    });
  });

  // ── GET with Descope RelayState ─────────────────────────────────────────────

  describe('GET with Descope RelayState query param', () => {
    it('rewrites to Descope ACS URL', async () => {
      const req = new IncomingRequest(`https://${HOSTNAME}/auth?RelayState=s%2Ftest`);
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      const url = new URL(called.url);
      expect(url.hostname).toBe(CNAME);
      expect(url.pathname).toBe('/v1/auth/saml/acs');
      expect(url.searchParams.get('projectId')).toBe(PROJECT_ID);
    });
  });

  // ── SSO logOnly ─────────────────────────────────────────────────────────────

  describe('SSO logOnly mode', () => {
    it('does not rewrite — forwards the original request', async () => {
      await callWorker(samlPost('logonly.example.com', 's/test'));
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe('logonly.example.com');
    });
  });

  // ── SCIM wildcard tenants ───────────────────────────────────────────────────

  describe('SCIM with tenants: "*"', () => {
    it('normalizes path and preserves original Authorization header', async () => {
      const req = new IncomingRequest(
        'https://scim-wildcard.example.com/scim/v2/connections/con_abc/Users',
        { headers: { Authorization: 'Bearer original-idp-token' } },
      );
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      const url = new URL(called.url);
      expect(url.hostname).toBe(CNAME);
      expect(url.pathname).toBe('/scim/v2/Users');
      expect(called.headers.get('Authorization')).toBe('Bearer original-idp-token');
    });
  });

  // ── SCIM tenant map — known connection ──────────────────────────────────────

  describe('SCIM with tenant map — known connection ID', () => {
    it('normalizes path and swaps Authorization header', async () => {
      const req = new IncomingRequest(
        `https://${HOSTNAME}/scim/v2/connections/con_test123/Users/user_456`,
        { headers: { Authorization: 'Bearer idp-token' } },
      );
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      const url = new URL(called.url);
      expect(url.hostname).toBe(CNAME);
      expect(url.pathname).toBe('/scim/v2/Users/user_456');
      expect(called.headers.get('Authorization')).toBe(`Bearer ${PROJECT_ID}:scim-token-abc`);
    });

    it('handles Groups resource type', async () => {
      const req = new IncomingRequest(
        `https://${HOSTNAME}/scim/v2/connections/con_test123/Groups`,
        { headers: { Authorization: 'Bearer idp-token' } },
      );
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).pathname).toBe('/scim/v2/Groups');
    });

    it('preserves POST method on SCIM create', async () => {
      const req = new IncomingRequest(
        `https://${HOSTNAME}/scim/v2/connections/con_test123/Users`,
        {
          method: 'POST',
          headers: {
            Authorization: 'Bearer idp-token',
            'Content-Type': 'application/scim+json',
          },
          body: JSON.stringify({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'test' }),
        },
      );
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(called.method).toBe('POST');
    });
  });

  // ── SCIM tenant map — other providers' URL shapes ───────────────────────────

  describe('SCIM with tenant map — provider URL shapes', () => {
    for (const path of [
      '/directory/resources/scim/v2.0/con_test123/Users', // Frontegg
      '/con_test123/scim/v2/Users', // Okta
    ]) {
      it(`finds the connection ID in ${path}`, async () => {
        const req = new IncomingRequest(`https://${HOSTNAME}${path}`, {
          headers: { Authorization: 'Bearer idp-token' },
        });
        await callWorker(req);
        const called: Request = mockFetch.mock.calls[0][0];
        expect(new URL(called.url).hostname).toBe(CNAME);
        expect(called.headers.get('Authorization')).toBe(`Bearer ${PROJECT_ID}:scim-token-abc`);
      });
    }

    it('rejects a Frontegg path with an unknown ID (v2.0 is not mistaken for one)', async () => {
      const req = new IncomingRequest(
        `https://${HOSTNAME}/directory/resources/scim/v2.0/con_unknown/Users`,
        { headers: { Authorization: 'Bearer idp-token' } },
      );
      const response = await callWorker(req);
      expect(response.status).toBe(401);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ── SCIM tenant map — incoming Authorization check ──────────────────────────

  describe('SCIM with tenant map — Authorization check', () => {
    const scimRequest = (connectionId: string, authorization?: string) =>
      new IncomingRequest(`https://${HOSTNAME}/scim/v2/connections/${connectionId}/Users`, {
        headers: authorization ? { Authorization: authorization } : {},
      });

    it('accepts any of the configured hashes (token rotation)', async () => {
      await callWorker(scimRequest('con_test123', 'Bearer rotated-idp-token'));
      const called: Request = mockFetch.mock.calls[0][0];
      expect(called.headers.get('Authorization')).toBe(`Bearer ${PROJECT_ID}:scim-token-abc`);
    });

    for (const [name, connectionId, authorization] of [
      ['a wrong token', 'con_test123', 'Bearer attacker-token'],
      ['a missing Authorization header', 'con_test123', undefined],
      ['a tenant with no authHashes configured', 'con_nohash', 'Bearer idp-token'],
    ] as const) {
      it(`returns 401 for ${name} without calling fetch`, async () => {
        const response = await callWorker(scimRequest(connectionId, authorization));
        expect(response.status).toBe(401);
        expect(mockFetch).not.toHaveBeenCalled();
      });
    }

    it('logOnly: a wrong token is logged as a would-be rejection and passed through unchanged', async () => {
      const req = new IncomingRequest(
        'https://scim-logonly-tenants.example.com/scim/v2/connections/con_test123/Users',
        { headers: { Authorization: 'Bearer attacker-token' } },
      );
      const response = await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(response.status).not.toBe(401);
      expect(new URL(called.url).hostname).toBe('scim-logonly-tenants.example.com');
      expect(called.headers.get('Authorization')).toBe('Bearer attacker-token');
    });
  });

  // ── SCIM tenant map — unknown connection ────────────────────────────────────

  describe('SCIM with tenant map — unknown connection ID', () => {
    it('returns 401 without calling fetch', async () => {
      const req = new IncomingRequest(
        `https://${HOSTNAME}/scim/v2/connections/con_unknown/Users`,
        { headers: { Authorization: 'Bearer idp-token' } },
      );
      const response = await callWorker(req);
      expect(response.status).toBe(401);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ── SCIM logOnly ────────────────────────────────────────────────────────────

  describe('SCIM logOnly mode', () => {
    it('does not rewrite — forwards the original request', async () => {
      const req = new IncomingRequest(
        'https://logonly.example.com/scim/v2/Users',
        { headers: { Authorization: 'Bearer original-token' } },
      );
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe('logonly.example.com');
    });

    it('with a tenant map and a known connection ID: logs the match and passes through unchanged', async () => {
      const req = new IncomingRequest(
        'https://scim-logonly-tenants.example.com/scim/v2/connections/con_test123/Users',
        { headers: { Authorization: 'Bearer original-token' } },
      );
      await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      // Not rewritten to the Descope CNAME/target — original request forwarded as-is
      expect(new URL(called.url).hostname).toBe('scim-logonly-tenants.example.com');
      // Authorization header is NOT swapped for the tenant's token
      expect(called.headers.get('Authorization')).toBe('Bearer original-token');
    });

    it('with a tenant map and an unrecognized connection ID: logs the rejection and passes through unchanged (no 401)', async () => {
      const req = new IncomingRequest(
        'https://scim-logonly-tenants.example.com/scim/v2/connections/con_unknown/Users',
        { headers: { Authorization: 'Bearer original-token' } },
      );
      const response = await callWorker(req);
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe('scim-logonly-tenants.example.com');
      expect(response.status).not.toBe(401);
    });
  });

  // ── normalizeScimPath (via SCIM proxy) ──────────────────────────────────────

  describe('SCIM path normalization', () => {
    const cases = [
      ['/scim/v2/connections/con_test123/Users', '/scim/v2/Users'],
      ['/scim/v2/connections/con_test123/Users/uid_123', '/scim/v2/Users/uid_123'],
      ['/scim/v2/connections/con_test123/Groups', '/scim/v2/Groups'],
      ['/scim/v2/connections/con_test123/Schemas', '/scim/v2/Schemas'],
      ['/scim/v2/connections/con_test123/ServiceProviderConfig', '/scim/v2/ServiceProviderConfig'],
      ['/scim/v2/connections/con_test123/ResourceTypes', '/scim/v2/ResourceTypes'],
      // Frontegg: https://<custom-domain>/directory/resources/scim/v2.0/<id>
      ['/directory/resources/scim/v2.0/con_test123/Users/uid_123', '/scim/v2/Users/uid_123'],
      // Okta inbound SCIM: https://<okta-domain>/<connectionId>/scim/v2
      ['/con_test123/scim/v2/Groups', '/scim/v2/Groups'],
    ] as const;

    for (const [input, expected] of cases) {
      it(`${input} → ${expected}`, async () => {
        const req = new IncomingRequest(`https://${HOSTNAME}${input}`, {
          headers: { Authorization: 'Bearer idp-token' },
        });
        await callWorker(req);
        const called: Request = mockFetch.mock.calls[0][0];
        expect(new URL(called.url).pathname).toBe(expected);
      });
    }
  });
});
