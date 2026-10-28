import projectConfig from './projectConfig.json';

type SsoConfig = {
  enabled?: boolean;  // defaults to true
  logOnly?: boolean;  // defaults to false — logs the intended rewrite but forwards the original request unchanged
  rewriteAnyRelayState?: boolean;  // defaults to false — also rewrite SAML responses carrying a non-Descope RelayState (breaks gradual migration: the old provider's SP-initiated responses would reach Descope)
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
const SCIM_RESOURCE_RE = new RegExp(`/(${SCIM_RESOURCE_TYPES})(/.*)?$`, 'i');

// Provider SCIM base URLs this worker can intercept (they live on the customer's custom domain):
//   Auth0:    /scim/v2/connections/<id>/Users
//   Frontegg: /directory/resources/scim/v2.0/<id>/Users
//   Okta:     /<id>/scim/v2/Users
function isScimPath(pathname: string): boolean {
  return /\/scim(\/|$)/i.test(pathname);
}

function normalizeScimPath(pathname: string): string {
  // Strip any provider-specific segments before the SCIM resource type.
  // e.g. /scim/v2/connections/con_xxx/Users/123 → /scim/v2/Users/123
  const match = pathname.match(SCIM_RESOURCE_RE);
  if (match) {
    return `/scim/v2/${match[1]}${match[2] ?? ''}`;
  }
  return pathname;
}

function findScimConnectionId(pathname: string, tenants: ScimTenantMap): string | null {
  // The connection ID is whichever path segment before the SCIM resource type is a key in the
  // tenant map — its position differs per provider (see isScimPath), so don't assume one.
  const match = pathname.match(SCIM_RESOURCE_RE);
  const prefix = match ? pathname.slice(0, match.index) : pathname;
  return prefix.split('/').find((segment) => Object.prototype.hasOwnProperty.call(tenants, segment)) ?? null;
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

    if (scimEnabled && isScimPath(requestUrl.pathname)) {
      const targetUrl = buildDescopeScimUrl(request.url, config);
      const scimTenants = config.scim!.tenants ?? '*';
      const scimLogOnly = config.scim?.logOnly ?? false;

      const scimHeaders = new Headers(request.headers);

      if (scimTenants === '*') {
        // All tenants allowed — forward original Authorization header as-is
        if (scimLogOnly) {
          console.log('[SCIM logOnly] would proxy to:', targetUrl, '(all tenants) — forwarding original request unchanged');
          return passThrough(request);
        }
        console.log('SCIM request detected (all tenants), proxying to:', targetUrl);
      } else {
        // Tenant map — look up the connection ID extracted from the SCIM path
        const tenantMap = scimTenants as ScimTenantMap;
        const connectionId = findScimConnectionId(requestUrl.pathname, tenantMap);

        if (!connectionId) {
          if (scimLogOnly) {
            console.warn('[SCIM logOnly] would reject — no recognized connection ID in path:', requestUrl.pathname, '— forwarding original request unchanged');
            return passThrough(request);
          }
          console.warn('SCIM request rejected — no recognized connection ID in path:', requestUrl.pathname, 'for hostname:', hostname);
          return new Response('Unauthorized', { status: 401 });
        }
        const tenantEntry = tenantMap[connectionId];

        if (scimLogOnly) {
          console.log('[SCIM logOnly] would proxy to:', targetUrl, 'for tenant:', tenantEntry.tenantId, '(connection:', connectionId, ') — forwarding original request unchanged');
          return passThrough(request);
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
        const samlResponse = formData.get('SAMLResponse')?.toString();
        const relayState = formData.get('RelayState')?.toString();

        if (!samlResponse) {
          console.log('Form POST without SAMLResponse, forwarding as-is');
        } else if (relayState?.startsWith('s/')) {
          console.log('Descope SP-initiated SAML request detected');
          shouldRewrite = true;
        } else if (!relayState) {
          console.log('IDP-initiated SAML request detected (no RelayState)');
          shouldRewrite = true;
        } else if (config.sso?.rewriteAnyRelayState) {
          console.log('SAML request with non-Descope RelayState detected, rewriting (rewriteAnyRelayState):', relayState);
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
