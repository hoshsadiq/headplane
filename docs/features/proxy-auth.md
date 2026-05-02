---
title: Proxy Authentication
description: Configure proxy-based authentication for Headplane using an upstream auth proxy.
outline: [2, 3]
---

# Proxy Authentication

Proxy authentication lets you put an auth proxy (Authelia, Authentik, Cloudflare Access, etc.) in
front of Headplane and have it handle the full OIDC flow. The proxy then forwards the authenticated
user's identity to Headplane via HTTP headers or a signed JWT. Headplane reads those headers,
provisions a session, and grants access without ever talking to an identity provider directly.

## When to Use This vs. OIDC

Both approaches end up with the same result: a logged-in user with a role. The difference is where
the OIDC handshake happens.

|                                 | Proxy Auth              | OIDC     |
| ------------------------------- | ----------------------- | -------- |
| OIDC client config in Headplane | Not needed              | Required |
| Auth proxy required             | Yes                     | No       |
| Works with non-OIDC providers   | Yes (proxy handles it)  | No       |
| JWT validation                  | Optional (per provider) | Always   |

Use proxy auth when you already have an auth proxy protecting your services and want Headplane to
participate in that setup without managing its own OIDC client. Use OIDC when you want Headplane to
handle authentication directly.

Both can be active at the same time. A user who signs in via OIDC and a user who signs in via proxy
are treated as separate accounts even if they represent the same person.

## How It Works

1. A request arrives at Headplane. The auth proxy has already authenticated the user and attached
   identity headers (and optionally a signed JWT) to the request.
2. Headplane reads the configured headers. If a JWT is present, it validates the signature before
   trusting the claims.
3. The subject value is normalized to `proxy:custom:{raw_value}` to keep it separate from OIDC
   subjects in the database.
4. Headplane looks up or creates a user record for that subject, then creates a session cookie.
5. On subsequent requests, the existing session is reused as long as the proxy still forwards the
   same identity headers.

## Configuration

Add a `proxy` section to your Headplane config file. You configure the identity headers and
(optionally) JWT validation directly:

```yaml
proxy:
  # Set to false to define the proxy section without activating it.
  # enabled: true

  # Which HTTP headers carry the user's identity.
  headers:
    subject: "Remote-User" # Required. Stable unique identifier for the user.
    email: "Remote-Email" # Optional.
    name: "Remote-Name" # Optional.


  # Restrict which source IPs are allowed to forward proxy headers. Accepts
  # individual IPs or CIDR ranges. If omitted, any IP can forward headers.
  # allowed_ips:
  #   - "10.0.0.0/8"
  #   - "172.16.0.0/12"

  # Where to redirect the user after they log out of Headplane. Without this,
  # Headplane destroys the session and returns to the login page, but the proxy
  # may immediately re-authenticate the user.
  # logout_url: "https://auth.example.com/logout"
```

### JWT Validation

When your provider sends a signed JWT, add a `jwt` block with the header name and key source.
Validated JWT claims take priority over the plain identity headers.

```yaml
proxy:
  headers:
    subject: "X-authentik-uid"
    email: "X-authentik-email"
  jwt:
    header: "X-authentik-jwt"
    key_source:
      kind: "dynamic_header"
      meta_header: "X-authentik-meta-jwks"
```

Supported `key_source` kinds:

| Kind             | Description                                        | Extra Fields      |
| ---------------- | -------------------------------------------------- | ----------------- |
| `jwks_url`       | Fetch keys from a static JWKS endpoint             | `url`             |
| `oidc_discovery` | Discover JWKS from the issuer's `.well-known` URL  | (uses `issuer`)   |
| `aws_alb_pem`    | Fetch per-kid PEM from the AWS public key endpoint | (uses `region`)   |
| `google_iap`     | Fetch from Google's IAP public key endpoint        | (uses `audience`) |
| `dynamic_header` | Read the JWKS URL from a request header at runtime | `meta_header`     |

JWKS responses are cached in memory for the lifetime of the process. ALB PEM keys are cached per
key ID.

## IP Whitelisting

The `allowed_ips` option restricts which source IPs can forward proxy headers. This is an important
defense-in-depth measure: without it, any client that can reach Headplane directly could forge
identity headers and authenticate as any user.

```yaml
proxy:
  allowed_ips:
    - "10.0.0.0/8"
    - "192.168.1.50"
```

::: warning
If you don't configure `allowed_ips`, Headplane logs a warning at startup. This is intentional.
Without IP whitelisting, the security of proxy auth depends entirely on your network topology
preventing direct access to Headplane. Make sure Headplane is not reachable except through the
auth proxy.
:::

Headplane reads the source IP from `X-Forwarded-For` (first entry) or `X-Real-IP`. If neither is
present, the request is allowed through (the proxy is presumably on the same host).

## Security Considerations

Proxy auth is only as secure as the trust boundary between your auth proxy and Headplane.

- **Network isolation**: Headplane should only be reachable through the auth proxy. If a client can
  reach Headplane directly, they can forge headers.
- **Header stripping**: Your auth proxy must strip any incoming identity headers from untrusted
  clients before forwarding the request. Most proxies do this by default, but verify your config.
- **JWT validation**: For providers that send JWTs, Headplane validates the signature. This provides
  cryptographic proof of identity even if headers could be forged.
- **Authelia**: Since Authelia doesn't send a JWT, security relies entirely on network isolation and
  header stripping. Use `allowed_ips` when running Authelia.

## Roles and First Login

The first user to sign in via proxy auth (when no users exist in the database at all) is assigned
the **Owner** role. All subsequent users get the **Member** role and need an admin to grant them
access.

This is the same bootstrap behavior as OIDC. If you already have users from OIDC, the first proxy
auth user gets the **Member** role.

## Coexistence with OIDC and API Keys

Proxy auth, OIDC, and API key login can all be active at the same time. Each method creates its own
session. A user who signs in via OIDC and the same person signing in via proxy are two separate
records in the database with different subjects.

If you want to disable API key login when using proxy auth, set `oidc.disable_api_key_login: true`
(this setting lives under `oidc` even when OIDC itself is not configured).

## Logout Behavior

When a user logs out, Headplane destroys the local session. If your auth proxy automatically
re-authenticates users (which most do), the user will be signed back in immediately on the next
request.

To get a real logout, configure `proxy.logout_url` to point at your proxy's logout endpoint. After
destroying the session, Headplane redirects the user there instead of back to the login page.

```yaml
proxy:
  logout_url: "https://auth.example.com/logout"
```

## Limitations

- **No group-to-role mapping**: Proxy auth does not read group claims from JWTs or headers. Role
  assignment is manual through the Users page.
- **Changing the subject header**: If you change `headers.subject`, existing users will not be
  matched. Their old records remain in the database but they'll get new accounts on next login.
- **Same person via OIDC and proxy**: If the same person authenticates through both OIDC and proxy
  auth, they get two separate user records. There's no automatic merging.

## Unconfigured Headers Warning

If Headplane receives auth-specific headers (like `Remote-User` or `X-authentik-uid`) but no
`proxy` section is configured, it logs a one-time warning per header name. This helps catch
misconfigured setups where the proxy is forwarding headers but Headplane isn't set up to use them.

Generic forwarding headers like `X-Forwarded-User` never trigger this warning.

## Provider Guides

Each provider needs different headers and JWT settings. Copy the relevant YAML block below into
your Headplane config.

### Authelia

Authelia forwards identity via plain headers. No JWT is involved.

```yaml
proxy:
  headers:
    subject: "Remote-User"
    email: "Remote-Email"
    name: "Remote-Name"
  allowed_ips:
    - "172.16.0.0/12" # Your Authelia container's network
```

In your Authelia config, make sure `headers.forwarded_user`, `forwarded_email`, and
`forwarded_name` are enabled for the Headplane upstream.

### Authentik

Authentik sends both a JWT (`X-authentik-jwt`) and plain headers. Headplane validates the JWT using
the JWKS URL from the `X-authentik-meta-jwks` header that Authentik also forwards.

```yaml
proxy:
  headers:
    subject: "X-authentik-uid"
    email: "X-authentik-email"
    name: "X-authentik-name"
  jwt:
    header: "X-authentik-jwt"
    key_source:
      kind: "dynamic_header"
      meta_header: "X-authentik-meta-jwks"
```

No extra config is needed. The JWKS URL is discovered per-request from the meta header.

### oauth2-proxy

oauth2-proxy forwards the upstream OIDC access token as a Bearer token in the `Authorization`
header. Headplane validates it using OIDC discovery.

```yaml
proxy:
  issuer: "https://your-idp.example.com"
  headers:
    subject: "X-Forwarded-Email"
    email: "X-Forwarded-Email"
    name: "X-Forwarded-Preferred-Username"
  jwt:
    header: "Authorization" # Bearer token
    key_source:
      kind: "oidc_discovery"
```

The `issuer` must match the OIDC issuer you configured in oauth2-proxy.

### AWS ALB

The ALB forwards a JWT in `x-amzn-oidc-data`. Headplane fetches the signing key from AWS's public
key endpoint using the `kid` from the JWT header.

```yaml
proxy:
  region: "us-east-1"
  headers:
    subject: "x-amzn-oidc-identity"
    email: "x-amzn-oidc-identity"
  jwt:
    header: "x-amzn-oidc-data"
    key_source:
      kind: "aws_alb_pem"
```

### Cloudflare Access

Cloudflare Access signs a JWT and forwards it in `Cf-Access-Jwt-Assertion`. Headplane validates it
against your team's JWKS endpoint.

```yaml
proxy:
  team: "your-team-name"
  headers:
    subject: "Cf-Access-Authenticated-User-Email"
    email: "Cf-Access-Authenticated-User-Email"
  jwt:
    header: "Cf-Access-Jwt-Assertion"
    key_source:
      kind: "jwks_url"
      url: "https://your-team-name.cloudflareaccess.com/cdn-cgi/access/certs"
```

The `team` value is the subdomain of `cloudflareaccess.com` for your organization (e.g. if your
Access URL is `your-team.cloudflareaccess.com`, use `your-team`).

### GCP IAP

GCP IAP signs a JWT and forwards it in `X-Goog-Iap-Jwt-Assertion`. Headplane validates it against
Google's IAP public keys and checks the `aud` claim against your configured audience.

```yaml
proxy:
  audience: "/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID"
  headers:
    subject: "X-Goog-Authenticated-User-Id"
    email: "X-Goog-Authenticated-User-Email"
  jwt:
    header: "X-Goog-Iap-Jwt-Assertion"
    key_source:
      kind: "google_iap"
```

The audience string is the IAP resource name for your backend service. Find it in the Google Cloud
Console under Security > Identity-Aware Proxy.
