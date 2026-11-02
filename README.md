![image](https://github.com/user-attachments/assets/facc14a2-22f4-4a80-9720-cad57f40a774)

# SSO Redirect Worker

This utility, used in Descope's SSO Migration Process, defines and deploys a `CloudFlare Worker` for defining the redirect logic necessary for migrating to Descope.

## 🔄 SSO Migration

If you have a previous SSO setup with a different authentication provider or a home-grown solution, usually, the tenant's IT management team is forced to re-configure the setup within their IdP to match the new authentication provider.
This can cause a lot of friction and unnecessary time consumption, especially when this process requires reaching out to the customers, changing, and testing the authentication.

To prevent this friction, Descope supports the ability to consume and eventually migrate the current customer's setup.

This creates a totally seamless user login experience for your end users with pre-configured IdPs, without forcing your tenant administrators to have to re-configure their SAML/OIDC settings on their end at all.

The following chart demonstrates your current implementation for Single-Sign-On:
<img width="832" alt="old-sp-sso-migration" src="https://github.com/user-attachments/assets/614ed3e7-e615-442f-bb28-aa38f73d87cf">


And this chart, demonstrates the implementation, post migration:
<img width="832" alt="new-sp-sso-migration" src="https://github.com/user-attachments/assets/4c067e67-2c76-4fc8-877a-ef3e302f82c3">


1. When the end user starts the SSO authentication, a Descope relay state will be created.
2. Once the user is redirected to the IdP, authentication happens as usual.
3. Once the authentication is complete, the IdP response returns to the same SP ACS URL the customer had set previously in the IdP's settings.
4. Using a DNS provider, the response will be redirected to Descope, passing all the needed parameters to complete the authentication.
5. Descope will handle the final response and authenticate the user.
6. The user will be authenticated and logged in.

This utility integrates with step #4 to perform the necessary redirection logic for Descope to accept all of the authentication parameters.

The worker supports two SAML flows:

- **SP-initiated**: The user starts login from your app. Descope sets a `RelayState` starting with `s/` on the SAML request, which is echoed back by the IdP in its POST response. The worker detects this and routes to the Descope ACS endpoint.
- **IDP-initiated**: The user starts login directly from the IdP (no prior SP request, no `RelayState`). The worker detects the absence of `RelayState` and routes to the Descope ACS endpoint with the project ID appended as `?projectId=...`.

Only form POSTs that carry a `SAMLResponse` are routed to Descope. Any other form POST is forwarded to the origin unchanged.

A `SAMLResponse` with a non-Descope `RelayState` is forwarded to the origin by default, so tenants still on the old provider keep working during a gradual migration. Set `sso.rewriteAnyRelayState` to route those to Descope too, once no tenant depends on the old provider.

A single worker instance can handle **multiple Descope projects** by mapping each incoming hostname to its own configuration in `src/projectConfig.json`.

The worker also supports **SCIM provisioning**. When it's enabled for a project, the worker proxies SCIM requests to Descope:

- It rewrites the provider's SCIM path to Descope's standard `/scim/v2/...` format. Auth0, Frontegg and Okta URL formats are supported.
- It finds the tenant from the connection ID in the path.
- It checks that the caller's `Authorization` header is the token the old provider issued.
- It then swaps in that tenant's Descope SCIM token.

The customer's IdP (Entra ID, Okta, OneLogin, …) keeps its existing SCIM URL and token.



## ❗ Prerequisites

Using CloudFlare as the DNS provider, a "Worker" is needed to process and redirect the requests using custom logic.

Follow these instructions to create and deploy a new Cloudflare Worker to handle the redirect.

1. Go to https://dash.cloudflare.com/
2. Create an Account level token:
    * Manage Account > Account API Tokens > Create token > "Edit Cloudflare Workers"

3. Copy the created token and export it as an environment variable locally:
```
export CLOUDFLARE_API_TOKEN=<CLOUDFLARE_TOKEN>
export CLOUDFLARE_ACCOUNT_ID=<YOUR_ACCOUNT_ID>   # found at dash.cloudflare.com (right sidebar)
```

4. [CloudFlare CLI](https://developers.cloudflare.com/cloudflare-one/tutorials/cli/) set up on your local machine.
5. `npm` / `yarn` / any other JavaScript package management tool installed.



## ⚙️ Setup

### 1. Clone the repo
```
git clone https://github.com/descope/sso-redirect-worker.git
```

### 2. Configure `wrangler.toml`

Set the route(s) the worker should handle:

```toml
[[routes]]
pattern = "login.example.com/*"  # the old ACS hostname your IdPs are pointed at
zone_name = "example.com"        # the Cloudflare-managed zone for that domain
```

Add additional `[[routes]]` blocks if you are serving multiple domains from a single worker deployment.

Your Cloudflare account ID is **not** stored in `wrangler.toml`. Supply it at deploy time via the environment variable:

```
export CLOUDFLARE_ACCOUNT_ID=<your-account-id>   # found at dash.cloudflare.com (right sidebar)
npm run deploy
```

Alternatively, `wrangler login` will auto-detect the account ID so no variable is needed.

### 3. Configure `src/projectConfig.json`

> **Important:** `src/projectConfig.json` is listed in `.gitignore` because it holds customer-specific values. Keep Descope SCIM tokens out of it: store each one as a Worker secret and reference it by name with `tokenSecret` (see the `scim` block below). **Never commit it with real values.**

Copy the example file and fill in your values:

```
cp src/projectConfig.example.json src/projectConfig.json
```

This file maps each incoming hostname to its Descope project. Each entry has a top-level `sso` and `scim` block that can be configured independently.

#### Full config reference

```json
{
  "login.example.com": {
    "newCname": "auth.example.com",
    "projectId": "YOUR_DESCOPE_PROJECT_ID",
    "sso": {
      "enabled": true,
      "logOnly": false
    },
    "scim": {
      "enabled": false,
      "logOnly": false,
      "tenants": {
        "<connection_id>": {
          "tenantId": "<descope_tenant_id>",
          "tokenSecret": "SCIM_TOKEN_TENANT_A",
          "authHashes": ["<sha256_of_old_provider_authorization_header>"]
        }
      }
    }
  }
}
```

#### Top-level fields

| Field | Description |
|---|---|
| key (hostname) | The hostname the worker receives requests on — must match the `[[routes]]` pattern in `wrangler.toml` |
| `newCname` | Your Descope custom domain (e.g. `auth.example.com`). If omitted, defaults to `api.descope.com` |
| `projectId` | Your Descope project ID, found in the Descope console |

#### `sso` block

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable or disable SSO proxying for this hostname |
| `logOnly` | `false` | When `true`, logs the intended rewrite but forwards the original request unchanged — useful for validating detection before going live |
| `rewriteAnyRelayState` | `false` | When `true`, a `SAMLResponse` with a non-Descope `RelayState` (e.g. IdP-initiated logins that send an app-specific one) is also routed to Descope. Leave it off during a gradual migration: the old provider's SP-initiated responses carry its own `RelayState` and would be sent to Descope |

SAML requests are rewritten to:
```
https://<newCname>/v1/auth/saml/acs?projectId=<projectId>
```

#### `scim` block

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable or disable SCIM proxying for this hostname |
| `logOnly` | `false` | When `true`, the worker still runs the full tenant lookup and `Authorization` check, but it only logs the outcome. It always forwards the original request to the old provider unchanged, instead of proxying to Descope or returning 401. Possible log lines: `[SCIM logOnly] would proxy to: ...` (everything matched); `[SCIM logOnly] would reject — no recognized connection ID in path: ...`; or `[SCIM logOnly] would reject — Authorization header does not match authHashes ...`, which also includes the incoming header's SHA-256 and the old provider's response status. Use it to validate routing, tenant recognition and token hashes before going live |
| `tenants` | `"*"` | `"*"` = proxy all requests and forward the original `Authorization` header as-is. Descope validates it, so it must already be a Descope token. Map = per-tenant token check and swap (see below) |

**Supported providers** — any request with a `/scim` path segment on the configured hostname is treated as SCIM. The worker can only intercept SCIM traffic that the old provider serves on the customer's own domain:

| Provider | SCIM base URL given to the IdP | Key in `tenants` |
|---|---|---|
| Auth0 | `https://<custom-domain>/scim/v2/connections/<id>` | `<id>` |
| Frontegg | `https://<custom-domain>/directory/resources/scim/v2.0/<id>` | `<id>` |
| Okta (inbound SCIM) | `https://<okta-domain>/<connectionId>/scim/v2` | `<connectionId>` |
| PingOne | `https://scim-api.pingone.<region>/environments/<envId>/v2` | **Not supported** — served on Ping's domain (no custom domain), authenticated with short-lived Worker-app access tokens. Repoint the SCIM client to Descope instead |

**Tenant map** — when `tenants` is an object, the worker looks at the path segments before the SCIM resource type and uses whichever one is a key in the map, regardless of its position or what it represents in your IdP (connection ID, tenant slug, org ID, etc.):

```
/scim/v2/connections/con_OVM407qBECcvwRSG/Users            →  key is "con_OVM407qBECcvwRSG"
/directory/resources/scim/v2.0/0f6b2c1e-.../Users          →  key is "0f6b2c1e-..."
/0oa1b2c3d4/scim/v2/Groups                                 →  key is "0oa1b2c3d4"
```

Each entry maps that segment to a Descope tenant, the Worker secret holding that tenant's Descope SCIM token, and the hashes of the old provider's token:

```json
"tenants": {
  "con_OVM407qBECcvwRSG": {
    "tenantId": "T2abc123",
    "tokenSecret": "SCIM_TOKEN_T2ABC123",
    "authHashes": ["<sha256 of the old provider's Authorization header>"]
  },
  "tenant_xyz": {
    "tenantId": "T2xyz456",
    "tokenSecret": "SCIM_TOKEN_T2XYZ456",
    "authHashes": ["<current token hash>", "<rotated token hash>"]
  }
}
```

- **`tokenSecret`** is the name of a [Worker secret](https://developers.cloudflare.com/workers/configuration/secrets/) whose value is the `Authorization` header to send to Descope, `Bearer <projectId>:<accessKey>`. Secrets are encrypted by Cloudflare and never appear in the config, the code, or the logs. Set one with:
  ```sh
  npx wrangler secret put SCIM_TOKEN_T2ABC123
  # paste: Bearer <projectId>:<accessKey>
  ```
  If the secret is missing at runtime, the request gets `500` and the worker logs `SCIM request failed — no Descope token ... Worker secret "<name>" is not set`. In `logOnly` mode it logs `[SCIM logOnly] would fail — no Descope token ...` instead.
  You can still put the value inline as `token`, but it's then stored as plaintext in the config, so prefer `tokenSecret`. When both are set, `tokenSecret` wins.
- **`authHashes` (required)** — SHA-256 hex digests of the full `Authorization` header value the customer's IdP sends today (the token the old provider issued). The connection ID in the URL is not a secret, so the worker only swaps in the Descope token when the incoming header matches one of these hashes. List more than one to cover token rotation. Compute a hash with:
  ```sh
  printf '%s' 'Bearer <old_provider_scim_token>' | shasum -a 256
  ```
  Don't have the old token? Run with `logOnly: true` and wait for the IdP's next sync. Each mismatch logs `incoming Authorization sha256: <hash>` and `old provider responded: <status>`. A 2xx from the old provider means the token is genuine, so copy that hash into `authHashes`. The token itself is never logged.
- Requests whose segment is found in the map **and** whose `Authorization` header matches `authHashes` have that header replaced with the mapped Descope token before being forwarded.
- Requests with **no** path segment in the map, a missing or non-matching `Authorization` header, or a tenant with no `authHashes` are rejected with `401 Unauthorized`. In `logOnly` mode a token mismatch is logged as `[SCIM logOnly] would reject — Authorization header does not match authHashes ...` — use this to confirm every tenant's hash before going live.
- The SCIM token can be generated in the Descope console under **Access Keys**.

**Path normalization** — the worker automatically strips provider-specific segments from the SCIM path and rewrites to the standard format:

```
/scim/v2/connections/con_abc/Users/123  →  /scim/v2/Users/123
/scim/v2/tenants/tenant_xyz/Groups      →  /scim/v2/Groups
/directory/resources/scim/v2.0/abc/Users →  /scim/v2/Users
/0oa1b2c3d4/scim/v2/Groups              →  /scim/v2/Groups
```

Supported SCIM resource types: `Users`, `Groups`, `Schemas`, `ServiceProviderConfig`, `ResourceTypes`, `Bulk`, `Me`.

#### SCIM migration walkthrough

For each tenant you're moving:

1. **Create the Descope side.** Create the tenant in Descope, and generate a SCIM access key for it under **Access Keys**. Store the key as a Worker secret with `npx wrangler secret put SCIM_TOKEN_<TENANT>`, using the value `Bearer <projectId>:<accessKey>`. In `tenants`, add an entry keyed by the old provider's connection ID, with `tenantId` and `tokenSecret: "SCIM_TOKEN_<TENANT>"`.
2. **Get the old token's hash.** If you have the old provider's SCIM token, hash it as shown above. If you don't, deploy with `scim.logOnly: true` and run `npx wrangler tail`. Then trigger a sync from the IdP ("Provision on demand" in Entra, "Force sync" in Okta) or wait for the next cycle. Copy the logged `incoming Authorization sha256` from a request where `old provider responded` is 2xx.
3. **Dry run.** Redeploy, still with `logOnly: true`. Every request from that tenant's IdP should now log `[SCIM logOnly] would proxy to: ... for tenant: <tenantId>`.
4. **Go live.** Set `logOnly: false` and redeploy. Requests are now verified, have their token swapped, and are sent to Descope. Unknown connection IDs and wrong tokens get `401`.

> **How the token check works:** the IdP sends `Authorization: <old provider token>`. The worker computes the SHA-256 of that full header value and compares it against `authHashes`. On a match, it replaces the header with the tenant's Descope token, read from the `tokenSecret` Worker secret, before forwarding. Descope validates that token as usual. The config only holds hashes of the old tokens and secret names, never a usable credential, and the worker never logs a raw token.

> **Upgrading from a version without `authHashes`:** this is a breaking change for tenant-map configs. Tenant entries without `authHashes` now get `401`. Add hashes, using step 2 if needed, before deploying with `logOnly: false`. `tenants: "*"` configs are unaffected.

#### Multiple projects example

```json
{
  "login.customer-a.com": {
    "newCname": "auth.customer-a.com",
    "projectId": "ProjectIdA",
    "sso": { "enabled": true, "logOnly": false },
    "scim": { "enabled": false }
  },
  "login.customer-b.com": {
    "newCname": "auth.customer-b.com",
    "projectId": "ProjectIdB",
    "sso": { "enabled": true, "logOnly": true },
    "scim": {
      "enabled": true,
      "logOnly": false,
      "tenants": {
        "con_xyz": {
          "tenantId": "T2tenant1",
          "tokenSecret": "SCIM_TOKEN_T2TENANT1",
          "authHashes": ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
        }
      }
    }
  }
}
```



## 🚀 Run & Deploy

```
npm i && npm run deploy
```



## ⚠️ Issue Reporting

For any issues or suggestions, feel free to open an issue in the GitHub repository.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
