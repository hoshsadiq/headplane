export type JwtClaims = { sub: string; email?: string; name?: string };
export type JwtValidator = (request: Request) => Promise<JwtClaims | null>;
export type ProxyIdentity = { subject: string; email?: string; name?: string };
export type IdentityResolver = (request: Request) => Promise<ProxyIdentity | null>;
export type ProxyPresetConfig = {
  key: string;
  headers: { subject: string; email?: string; name?: string };
};

export const GCP_IAP_EMAIL_PREFIX = "accounts.google.com:";
export const GCP_IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";

export const AUTH_SPECIFIC_PROXY_HEADERS = new Set([
  "remote-user",
  "x-authentik-uid",
  "cf-access-authenticated-user-email",
  "x-amzn-oidc-identity",
  "x-goog-authenticated-user-email",
]);
