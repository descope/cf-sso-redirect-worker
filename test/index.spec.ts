import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

// ── Constants ─────────────────────────────────────────────────────────────────
// vi.hoisted ensures these are available inside the vi.mock factory below,
// which is hoisted to run before any imports are evaluated.

const { HOSTNAME, CNAME, PROJECT_ID } = vi.hoisted(() => ({
  HOSTNAME: 'login.example.com',
  CNAME: 'auth.example.com',
  PROJECT_ID: 'TestProjectId123',
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
          },
        },
      },
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
    it('forwards the original request unchanged', async () => {
      await callWorker(samlPost(HOSTNAME, 'some-other-value'));
      const called: Request = mockFetch.mock.calls[0][0];
      expect(new URL(called.url).hostname).toBe(HOSTNAME);
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
        { headers: { Authorization: 'Bearer idp-original-token' } },
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
