import { createRemoteJWKSet, importSPKI, jwtVerify } from "jose";
import type { FlattenedJWSInput, JWSHeaderParameters } from "jose";

import type { ProxyConfig } from "~/server/config/config-schema";
import log from "~/utils/log";

export type JwtClaims = { sub: string; email?: string; name?: string };
export type JwtValidator = (request: Request) => Promise<JwtClaims | null>;

const GOOGLE_IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";

type KeyResolverFn = (
  protectedHeader: JWSHeaderParameters,
  token: FlattenedJWSInput,
) => Promise<CryptoKey | Uint8Array>;

const jwksCache = new Map<string, KeyResolverFn>();
const pemKeyCache = new Map<string, CryptoKey>();

function getOrCreateJwks(url: string): KeyResolverFn {
  let resolver = jwksCache.get(url);
  if (!resolver) {
    resolver = createRemoteJWKSet(new URL(url));
    jwksCache.set(url, resolver);
  }
  return resolver;
}

type JwtKeySource =
  | { kind: "jwks_url"; url: string }
  | { kind: "oidc_discovery" }
  | { kind: "aws_alb_pem" }
  | { kind: "google_iap" }
  | { kind: "dynamic_header"; meta_header: string };

export type JwtValidatorConfig = {
  header: string;
  key_source: JwtKeySource;
};

export function createJwtValidator(
  jwtConfig: JwtValidatorConfig,
  config: ProxyConfig,
): JwtValidator {
  const { header: jwtHeader, key_source: keySource } = jwtConfig;
  const isGcpIap = keySource.kind === "google_iap";
  const issuer = config.issuer;

  let staticResolver: KeyResolverFn | undefined;
  switch (keySource.kind) {
    case "jwks_url": {
      staticResolver = getOrCreateJwks(keySource.url);
      break;
    }
    case "google_iap":
      staticResolver = getOrCreateJwks(GOOGLE_IAP_JWKS_URL);
      break;
  }

  let discoveredResolver: KeyResolverFn | undefined;
  let discoveryInFlight: Promise<KeyResolverFn | null> | undefined;

  return async (request: Request): Promise<JwtClaims | null> => {
    const rawToken = extractToken(request, jwtHeader);
    if (!rawToken) return null;

    try {
      const resolver = await pickResolver(request);
      if (!resolver) return null;

      const { payload } = await jwtVerify(rawToken, resolver, {
        ...(config.audience ? { audience: config.audience } : {}),
        ...(issuer ? { issuer } : {}),
      });

      if (!payload.sub) {
        log.debug("auth", "JWT validation failed: missing sub claim");
        return null;
      }

      let email = typeof payload["email"] === "string" ? (payload["email"] as string) : undefined;
      const name = typeof payload["name"] === "string" ? (payload["name"] as string) : undefined;

      if (isGcpIap && email?.startsWith("accounts.google.com:")) {
        email = email.slice("accounts.google.com:".length);
      }

      return { sub: payload.sub, email, name };
    } catch (cause) {
      const reason = cause instanceof Error ? cause.message : String(cause);
      log.debug("auth", "JWT validation failed: %s", reason);
      return null;
    }
  };

  async function pickResolver(request: Request): Promise<KeyResolverFn | null> {
    if (staticResolver) return staticResolver;

    switch (keySource.kind) {
      case "oidc_discovery":
        return resolveViaOidcDiscovery();
      case "aws_alb_pem":
        return createAlbResolver(config.region || "");
      case "dynamic_header":
        return resolveDynamicHeader(request, keySource.meta_header);
      default:
        return null;
    }
  }

  async function resolveViaOidcDiscovery(): Promise<KeyResolverFn | null> {
    if (discoveredResolver) return discoveredResolver;
    if (!discoveryInFlight) {
      discoveryInFlight = fetchOidcDiscovery();
    }
    const resolver = await discoveryInFlight;
    if (resolver) discoveredResolver = resolver;
    return resolver;
  }

  async function fetchOidcDiscovery(): Promise<KeyResolverFn | null> {
    if (!issuer) {
      log.debug("auth", "OIDC discovery requires an issuer in proxy config");
      return null;
    }

    try {
      const discoveryUrl = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
      const response = await fetch(discoveryUrl, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });

      if (!response.ok) {
        log.debug("auth", "OIDC discovery returned %d for %s", response.status, discoveryUrl);
        return null;
      }

      const metadata = (await response.json()) as Record<string, unknown>;
      const jwksUri = metadata.jwks_uri;
      if (typeof jwksUri !== "string") {
        log.debug("auth", "OIDC discovery response missing jwks_uri");
        return null;
      }

      return getOrCreateJwks(jwksUri);
    } catch (cause) {
      discoveryInFlight = undefined;
      const reason = cause instanceof Error ? cause.message : String(cause);
      log.debug("auth", "OIDC discovery failed: %s", reason);
      return null;
    }
  }
}

function createAlbResolver(region: string): KeyResolverFn {
  return async (header) => {
    const kid = header.kid;
    if (!kid) throw new Error("ALB JWT missing kid in header");

    const cached = pemKeyCache.get(kid);
    if (cached) return cached;

    const url = `https://public-keys.auth.elb.${region}.amazonaws.com/${kid}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    if (!response.ok) {
      throw new Error(`ALB public key fetch returned ${response.status}`);
    }

    const pem = await response.text();
    const key = (await importSPKI(pem, "ES256")) as CryptoKey;
    pemKeyCache.set(kid, key);
    return key;
  };
}

function resolveDynamicHeader(request: Request, metaHeader: string): KeyResolverFn | null {
  const jwksUrl = request.headers.get(metaHeader);
  if (!jwksUrl) {
    log.debug("auth", "Dynamic JWKS header %s not found in request", metaHeader);
    return null;
  }
  return getOrCreateJwks(jwksUrl);
}

function extractToken(request: Request, header: string): string | null {
  const value = request.headers.get(header);
  if (!value) return null;

  if (header.toLowerCase() === "authorization") {
    if (!value.startsWith("Bearer ")) return null;
    return value.slice(7);
  }

  return value;
}
