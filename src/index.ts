import projectConfig from './projectConfig.json';

type SsoConfig = {
  enabled?: boolean;  // defaults to true
  logOnly?: boolean;  // defaults to false — logs the intended rewrite but forwards the original request unchanged
};

// SCIM tenants: '*' = pass all requests through without token replacement
// Record: connection ID extracted from the SCIM URL path (e.g. "con_OVM407qBECcvwRSG") → { tenantId, token }
type ScimTenantEntry = {
  tenantId: string; // Descope tenant ID — used for identification and logging
  token: string;    // Authorization header value to forward to Descope, e.g. "Bearer <projectId>:<scimToken>"
};

type ScimTenantMap = Record<string, ScimTenantEntry>;

type ScimConfig = {
  enabled?: boolean;             // defaults to false
  logOnly?: boolean;             // defaults to false — logs the intended rewrite but forwards the original request unchanged
  tenants?: '*' | ScimTenantMap; // '*' = allow all, pass through as-is; map = per-tenant token swap
};

type ProjectConfig = {
  newCname?: string;
  projectId: string;
  sso?: SsoConfig;
  scim?: ScimConfig;
};

// Appended to sub-requests that should pass through to origin unchanged.
// On re-entry the worker detects this header, strips it, and bypasses all
// rewrite logic — preventing a route-triggered infinite loop (CF error 1042).
const PASS_HEADER = 'x-cf-no-redirect';

function normalizeHostname(newCname?: string): string {
  if (!newCname) {
    return 'api.descope.com';
  }

  try {
    // Handles values like "https://auth.example.com"
    return new URL(newCname).hostname;
  } catch {
    // Handles plain hostnames like "auth.example.com"
    return newCname
      .replace(/^https?:\/\//i, '')
      .replace(/\/.*$/, '');
  }
}

function buildDescopeAcsUrl(inputUrl: string, config: ProjectConfig): string {
  const url = new URL(inputUrl);

  url.protocol = 'https:';
  url.hostname = normalizeHostname(config.newCname);
  url.pathname = '/v1/auth/saml/acs';
  url.searchParams.set('projectId', config.projectId);

  return url.toString();
}

const SCIM_RESOURCE_TYPES = 'Users|Groups|Schemas|ServiceProviderConfig|ResourceTypes|Bulk|Me';

function normalizeScimPath(pathname: string): string {
  // Strip any provider-specific segments between /scim/v2/ and the SCIM resource type.
  // e.g. /scim/v2/connections/con_xxx/Users/123 → /scim/v2/Users/123
  const match = pathname.match(new RegExp(`/(${SCIM_RESOURCE_TYPES})(/.*)?$`, 'i'));
  if (match) {
    return `/scim/v2/${match[1]}${match[2] ?? ''}`;
  }
  return pathname;
}

function extractScimConnectionId(pathname: string): string | null {
  // Grab the segment immediately before the SCIM resource type.
  // e.g. /scim/v2/connections/con_OVM407qBECcvwRSG/Users → "con_OVM407qBECcvwRSG"
  // e.g. /scim/v2/Users → null (no provider-specific segment)
  const match = pathname.match(new RegExp(`/([^/]+)/(${SCIM_RESOURCE_TYPES})(?:/.*)?$`, 'i'));
  if (!match) return null;
  const candidate = match[1];
  // Exclude standard path segments that are not connection IDs
  if (candidate === 'v2') return null;
  return candidate;
}

function buildDescopeScimUrl(inputUrl: string, config: ProjectConfig): string {
  const url = new URL(inputUrl);

  url.protocol = 'https:';
  url.hostname = normalizeHostname(config.newCname);
  url.pathname = normalizeScimPath(url.pathname);

  return url.toString();
}

function passThrough(request: Request): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.set(PASS_HEADER, '1');
  return fetch(new Request(request.url, {
    method: request.method,
    headers,
    body: request.body,
    redirect: request.redirect,
  }));
}

export default {
  async fetch(request, _env, _ctx): Promise<Response> {
    // Short-circuit: sentinel set by a prior passThrough() call.
    // Strip the header so origin does not see it, then forward.
    if (request.headers.get(PASS_HEADER)) {
      const headers = new Headers(request.headers);
      headers.delete(PASS_HEADER);
      return fetch(new Request(request.url, {
        method: request.method,
        headers,
        body: request.body,
        redirect: request.redirect,
      }));
    }

    const requestUrl = new URL(request.url);
    const hostname = requestUrl.hostname;

    const config = (projectConfig as Record<string, ProjectConfig>)[hostname];

    if (!config) {
      console.log('No config found for hostname, forwarding as-is:', hostname);
      return passThrough(request);
    }

    console.log('Incoming request for hostname:', hostname, request.method, requestUrl.pathname);

    // ── SCIM ──────────────────────────────────────────────────────────────────
    const scimEnabled = config.scim?.enabled ?? false;

    if (scimEnabled && requestUrl.pathname.startsWith('/scim')) {
      const targetUrl = buildDescopeScimUrl(request.url, config);
      const scimTenants = config.scim!.tenants ?? '*';

      if (config.scim?.logOnly) {
        console.log('[SCIM logOnly] would proxy to:', targetUrl, '— forwarding original request unchanged');
        return passThrough(request);
      }

      const scimHeaders = new Headers(request.headers);

      if (scimTenants === '*') {
        // All tenants allowed — forward original Authorization header as-is
        console.log('SCIM request detected (all tenants), proxying to:', targetUrl);
      } else {
        // Tenant map — look up the connection ID extracted from the SCIM path
        const connectionId = extractScimConnectionId(requestUrl.pathname);

        if (!connectionId) {
          console.warn('SCIM request rejected — could not extract connection ID from path:', requestUrl.pathname);
          return new Response('Unauthorized', { status: 401 });
        }

        const tenantEntry = (scimTenants as ScimTenantMap)[connectionId];

        if (!tenantEntry) {
          console.warn('SCIM request rejected — unrecognized connection ID:', connectionId, 'for hostname:', hostname);
          return new Response('Unauthorized', { status: 401 });
        }

        console.log('SCIM request detected for tenant:', tenantEntry.tenantId, '(connection:', connectionId, ') — proxying to:', targetUrl);
        scimHeaders.set('Authorization', tenantEntry.token);
      }

      return fetch(new Request(targetUrl, {
        method: request.method,
        headers: scimHeaders,
        body: request.body,
        redirect: request.redirect,
      }));
    }

    // ── SSO ───────────────────────────────────────────────────────────────────
    const ssoEnabled = config.sso?.enabled ?? true;

    if (!ssoEnabled) {
      console.log('SSO disabled for hostname, forwarding as-is:', hostname);
      return passThrough(request);
    }

    let shouldRewrite = false;

    if (request.method === 'POST') {
      const contentType = request.headers.get('Content-Type') || '';

      if (contentType.includes('application/x-www-form-urlencoded')) {
        const formData = await request.clone().formData();
        const relayState = formData.get('RelayState')?.toString();

        if (relayState?.startsWith('s/')) {
          console.log('Descope SP-initiated SAML request detected');
          shouldRewrite = true;
        } else if (!relayState) {
          console.log('IDP-initiated SAML request detected (no RelayState)');
          shouldRewrite = true;
        } else {
          console.log('RelayState exists but not Descope format, forwarding as-is:', relayState);
        }
      } else {
        console.warn('Unexpected Content-Type for SAML POST binding, forwarding as-is:', contentType);
      }
    }

    const relayStateQueryParam = requestUrl.searchParams.get('RelayState');
    if (relayStateQueryParam?.startsWith('s/')) {
      console.log('Descope SAML request detected in query params');
      shouldRewrite = true;
    }

    if (!shouldRewrite) {
      console.log('No SSO rewrite conditions met, forwarding original request');
      return passThrough(request);
    }

    const targetUrl = buildDescopeAcsUrl(request.url, config);

    if (config.sso?.logOnly) {
      console.log('[SSO logOnly] would proxy to:', targetUrl, '— forwarding original request unchanged');
      return passThrough(request);
    }

    console.log('Proxying to Descope ACS:', targetUrl);
    return fetch(new Request(targetUrl, request));
  },
} satisfies ExportedHandler<Env>;
