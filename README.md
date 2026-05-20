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

A single worker instance can handle **multiple Descope projects** by mapping each incoming hostname to its own configuration in `src/projectConfig.json`.

The worker also supports **SCIM provisioning** — when enabled per project, SCIM requests are proxied to Descope with path normalization and per-tenant token swapping based on the connection ID in the request path.



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

> **Important:** `src/projectConfig.json` is listed in `.gitignore` because it contains SCIM bearer tokens. **Never commit it with real values.**

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
          "token": "Bearer <descope_project_id>:<descope_scim_token>"
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

SAML requests are rewritten to:
```
https://<newCname>/v1/auth/saml/acs?projectId=<projectId>
```

#### `scim` block

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable or disable SCIM proxying for this hostname |
| `logOnly` | `false` | When `true`, logs the intended rewrite but forwards the original request unchanged — useful for validating detection before going live |
| `tenants` | `"*"` | `"*"` = proxy all requests, forwarding the original `Authorization` header as-is; map = per-tenant token swap (see below) |

**Tenant map** — when `tenants` is an object, each key must equal the path segment that appears **immediately before the SCIM resource type** in the incoming URL, regardless of what that segment represents in your IdP (connection ID, tenant slug, org ID, etc.):

```
/scim/v2/connections/con_OVM407qBECcvwRSG/Users  →  key is "con_OVM407qBECcvwRSG"
/scim/v2/tenants/tenant_xyz/Groups               →  key is "tenant_xyz"
/scim/v2/orgs/org_abc/Users                      →  key is "org_abc"
```

Each entry maps that segment to a Descope tenant and its SCIM token:

```json
"tenants": {
  "con_OVM407qBECcvwRSG": {
    "tenantId": "T2abc123",
    "token": "Bearer <projectId>:<scimToken>"
  },
  "tenant_xyz": {
    "tenantId": "T2xyz456",
    "token": "Bearer <projectId>:<anotherScimToken>"
  }
}
```

- Requests whose segment is found in the map have their `Authorization` header replaced with the mapped Descope token before being forwarded.
- Requests whose segment is **not** in the map are rejected with `401 Unauthorized`.
- The SCIM token can be generated in the Descope console under **Access Keys**.

**Path normalization** — the worker automatically strips provider-specific segments from the SCIM path and rewrites to the standard format:

```
/scim/v2/connections/con_abc/Users/123  →  /scim/v2/Users/123
/scim/v2/tenants/tenant_xyz/Groups      →  /scim/v2/Groups
```

Supported SCIM resource types: `Users`, `Groups`, `Schemas`, `ServiceProviderConfig`, `ResourceTypes`, `Bulk`, `Me`.

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
          "token": "Bearer ProjectIdB:scimToken1"
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
