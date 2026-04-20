import projectConfig from './projectConfig.json';

type ProjectConfig = {
  newCname?: string;
  projectId: string;
};

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

export default {
  async fetch(request, _env, _ctx): Promise<Response> {
    const requestUrl = new URL(request.url);
    const hostname = requestUrl.hostname;
    const config = (projectConfig as Record<string, ProjectConfig>)[hostname];

    let targetUrl = request.url;
    let shouldRewrite = false;

    if (!config) {
      console.log('No config found for hostname, forwarding as-is:', hostname);
    } else {
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
            console.log(
              'RelayState exists but not Descope format, forwarding as-is:',
              relayState
            );
          }
        } else {
          console.warn(
            'Unexpected Content-Type for SAML POST binding, forwarding as-is:',
            contentType
          );
        }
      }

      const relayStateQueryParam = requestUrl.searchParams.get('RelayState');
      if (relayStateQueryParam?.startsWith('s/')) {
        console.log('Descope SAML request detected in query params');
        shouldRewrite = true;
      }

      if (shouldRewrite) {
        targetUrl = buildDescopeAcsUrl(request.url, config);
        console.log('Proxying to Descope ACS:', targetUrl);
      } else {
        console.log('No rewrite conditions met, forwarding original request:', targetUrl);
      }
    }

    const proxiedRequest = new Request(targetUrl, request);
    return fetch(proxiedRequest);
  },
} satisfies ExportedHandler<Env>;