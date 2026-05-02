import { SignJWT, exportJWK, exportSPKI, generateKeyPair } from "jose";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

import type { ProxyConfig } from "~/server/config/config-schema";
import { createJwtValidator, type JwtValidatorConfig } from "~/server/proxy/jwt";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

let rsaPrivateKey: CryptoKey;
let rsaPublicJwk: Record<string, unknown>;
let ecPrivateKey: CryptoKey;
let ecPublicPem: string;
let wrongRsaPrivateKey: CryptoKey;

beforeAll(async () => {
  const rsa = await generateKeyPair("RS256");
  rsaPrivateKey = rsa.privateKey as CryptoKey;
  const rsaExported = await exportJWK(rsa.publicKey);
  rsaPublicJwk = { ...rsaExported, kid: "test-key", use: "sig", alg: "RS256" };

  const ec = await generateKeyPair("ES256");
  ecPrivateKey = ec.privateKey as CryptoKey;
  ecPublicPem = await exportSPKI(ec.publicKey as CryptoKey);

  const wrongRsa = await generateKeyPair("RS256");
  wrongRsaPrivateKey = wrongRsa.privateKey as CryptoKey;
});

afterEach(() => {
  vi.restoreAllMocks();
});

function mockFetch(handler: (url: string) => Response | null) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : (input as Request).url;
    return handler(url) ?? new Response("Not found", { status: 404 });
  });
}

async function signJwt(
  claims: Record<string, unknown>,
  opts?: {
    key?: CryptoKey;
    alg?: string;
    kid?: string;
    expired?: boolean;
    audience?: string;
    issuer?: string;
  },
) {
  const builder = new SignJWT(claims)
    .setProtectedHeader({ alg: opts?.alg ?? "RS256", kid: opts?.kid ?? "test-key" })
    .setIssuedAt();

  if (opts?.expired) {
    builder.setExpirationTime(Math.floor(Date.now() / 1000) - 60);
  } else {
    builder.setExpirationTime("5m");
  }

  if (opts?.audience) builder.setAudience(opts.audience);
  if (opts?.issuer) builder.setIssuer(opts.issuer);

  return builder.sign(opts?.key ?? rsaPrivateKey);
}

function makeConfig(overrides?: Partial<ProxyConfig>): ProxyConfig {
  return { enabled: true, ...overrides } as ProxyConfig;
}

function jwksJson(keys: Record<string, unknown>[]) {
  return new Response(JSON.stringify({ keys }), {
    headers: { "Content-Type": "application/json" },
  });
}

describe("createJwtValidator", () => {
  test("valid JWT returns claims with sub, email, and name", async () => {
    const url = "https://valid-jwt.example.com/jwks";
    mockFetch((u) => (u === url ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "X-Test-JWT",
      key_source: { kind: "jwks_url", url },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    const token = await signJwt({ sub: "user-1", email: "u@test.com", name: "User One" });
    const result = await validate(
      new Request("http://localhost", { headers: { "X-Test-JWT": token } }),
    );

    expect(result).toEqual({ sub: "user-1", email: "u@test.com", name: "User One" });
  });

  test("expired JWT returns null", async () => {
    const url = "https://expired-jwt.example.com/jwks";
    mockFetch((u) => (u === url ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "X-JWT",
      key_source: { kind: "jwks_url", url },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    const token = await signJwt({ sub: "user-1" }, { expired: true });

    expect(
      await validate(new Request("http://localhost", { headers: { "X-JWT": token } })),
    ).toBeNull();
  });

  test("invalid signature returns null", async () => {
    const url = "https://bad-sig.example.com/jwks";
    mockFetch((u) => (u === url ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "X-JWT",
      key_source: { kind: "jwks_url", url },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    const token = await signJwt({ sub: "user-1" }, { key: wrongRsaPrivateKey });

    expect(
      await validate(new Request("http://localhost", { headers: { "X-JWT": token } })),
    ).toBeNull();
  });

  test("missing sub claim returns null", async () => {
    const url = "https://no-sub.example.com/jwks";
    mockFetch((u) => (u === url ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "X-JWT",
      key_source: { kind: "jwks_url", url },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    const token = await signJwt({ email: "u@test.com" });

    expect(
      await validate(new Request("http://localhost", { headers: { "X-JWT": token } })),
    ).toBeNull();
  });

  test("resolves keys from JWKS URL and verifies fetch was called", async () => {
    const url = "https://jwks-resolve.example.com/jwks";
    const spy = mockFetch((u) => (u === url ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "X-JWT",
      key_source: { kind: "jwks_url", url },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    const token = await signJwt({ sub: "user-1" });
    const result = await validate(new Request("http://localhost", { headers: { "X-JWT": token } }));

    expect(result?.sub).toBe("user-1");
    expect(spy).toHaveBeenCalled();
  });

  test("discovers JWKS URI via OIDC discovery", async () => {
    const issuer = "https://oidc-disco.example.com";
    const jwksUrl = `${issuer}/jwks`;

    mockFetch((u) => {
      if (u === `${issuer}/.well-known/openid-configuration`) {
        return new Response(JSON.stringify({ jwks_uri: jwksUrl }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (u === jwksUrl) return jwksJson([rsaPublicJwk]);
      return null;
    });

    const jwtConfig: JwtValidatorConfig = {
      header: "X-JWT",
      key_source: { kind: "oidc_discovery" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig({ issuer }));
    const token = await signJwt({ sub: "user-1" }, { issuer });
    const result = await validate(new Request("http://localhost", { headers: { "X-JWT": token } }));

    expect(result?.sub).toBe("user-1");
  });

  test("fetches per-kid PEM from AWS ALB endpoint", async () => {
    const region = "us-east-1";
    const kid = "alb-kid-abc";

    mockFetch((u) => {
      if (u === `https://public-keys.auth.elb.${region}.amazonaws.com/${kid}`) {
        return new Response(ecPublicPem, { headers: { "Content-Type": "text/plain" } });
      }
      return null;
    });

    const jwtConfig: JwtValidatorConfig = {
      header: "x-amzn-oidc-data",
      key_source: { kind: "aws_alb_pem" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig({ region }));
    const token = await signJwt({ sub: "alb-user" }, { key: ecPrivateKey, alg: "ES256", kid });
    const result = await validate(
      new Request("http://localhost", { headers: { "x-amzn-oidc-data": token } }),
    );

    expect(result?.sub).toBe("alb-user");
  });

  test("reads JWKS URL from request header (dynamic_header)", async () => {
    const jwksUrl = "https://authentik-dyn.example.com/o/app/jwks/";

    mockFetch((u) => (u === jwksUrl ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "X-authentik-jwt",
      key_source: { kind: "dynamic_header", meta_header: "X-authentik-meta-jwks" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    const token = await signJwt({ sub: "authentik-user" });
    const result = await validate(
      new Request("http://localhost", {
        headers: {
          "X-authentik-jwt": token,
          "X-authentik-meta-jwks": jwksUrl,
        },
      }),
    );

    expect(result?.sub).toBe("authentik-user");
  });

  test("caches ALB PEM key by kid across calls", async () => {
    const region = "eu-west-1";
    const kid = "cache-kid-xyz";

    const spy = mockFetch((u) => {
      if (u === `https://public-keys.auth.elb.${region}.amazonaws.com/${kid}`) {
        return new Response(ecPublicPem, { headers: { "Content-Type": "text/plain" } });
      }
      return null;
    });

    const jwtConfig: JwtValidatorConfig = {
      header: "x-amzn-oidc-data",
      key_source: { kind: "aws_alb_pem" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig({ region }));

    const token1 = await signJwt({ sub: "user-a" }, { key: ecPrivateKey, alg: "ES256", kid });
    expect(
      await validate(new Request("http://localhost", { headers: { "x-amzn-oidc-data": token1 } })),
    ).not.toBeNull();

    const token2 = await signJwt({ sub: "user-b" }, { key: ecPrivateKey, alg: "ES256", kid });
    expect(
      await validate(new Request("http://localhost", { headers: { "x-amzn-oidc-data": token2 } })),
    ).not.toBeNull();

    const pemFetches = spy.mock.calls.filter((call) => {
      const u =
        typeof call[0] === "string"
          ? call[0]
          : call[0] instanceof URL
            ? call[0].href
            : (call[0] as Request).url;
      return u.includes("public-keys.auth.elb");
    });
    expect(pemFetches).toHaveLength(1);
  });

  test("strips accounts.google.com: prefix from GCP IAP email", async () => {
    const jwksUrl = "https://www.gstatic.com/iap/verify/public_key-jwk";

    mockFetch((u) => (u === jwksUrl ? jwksJson([rsaPublicJwk]) : null));

    const jwtConfig: JwtValidatorConfig = {
      header: "x-goog-iap-jwt-assertion",
      key_source: { kind: "google_iap" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig({ audience: "test-aud" }));
    const token = await signJwt(
      {
        sub: "accounts.google.com:1234",
        email: "accounts.google.com:user@example.com",
        name: "Test User",
      },
      { audience: "test-aud" },
    );

    const result = await validate(
      new Request("http://localhost", { headers: { "x-goog-iap-jwt-assertion": token } }),
    );

    expect(result).not.toBeNull();
    expect(result!.sub).toBe("accounts.google.com:1234");
    expect(result!.email).toBe("user@example.com");
    expect(result!.name).toBe("Test User");
  });

  test("strips Bearer prefix from Authorization header", async () => {
    const issuer = "https://oauth2-bearer.example.com";
    const jwksUrl = `${issuer}/jwks`;

    mockFetch((u) => {
      if (u === `${issuer}/.well-known/openid-configuration`) {
        return new Response(JSON.stringify({ jwks_uri: jwksUrl }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (u === jwksUrl) return jwksJson([rsaPublicJwk]);
      return null;
    });

    const jwtConfig: JwtValidatorConfig = {
      header: "Authorization",
      key_source: { kind: "oidc_discovery" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig({ issuer }));
    const token = await signJwt({ sub: "user-1" }, { issuer });
    const result = await validate(
      new Request("http://localhost", { headers: { Authorization: `Bearer ${token}` } }),
    );

    expect(result?.sub).toBe("user-1");
  });

  test("returns null when JWT header is not present", async () => {
    const jwtConfig: JwtValidatorConfig = {
      header: "X-JWT",
      key_source: { kind: "jwks_url", url: "https://noop.example.com/jwks" },
    };

    const validate = createJwtValidator(jwtConfig, makeConfig());
    expect(await validate(new Request("http://localhost"))).toBeNull();
  });

  test("rejects non-HTTPS JWKS URL from dynamic header", async () => {
    const jwtConfig: JwtValidatorConfig = {
      header: "X-authentik-jwt",
      key_source: { kind: "dynamic_header", meta_header: "X-authentik-meta-jwks" },
    };

    const token = await signJwt({ sub: "user-http", email: "http@test.com" });
    const validate = createJwtValidator(jwtConfig, makeConfig());
    const request = new Request("http://localhost", {
      headers: {
        "X-authentik-jwt": token,
        "X-authentik-meta-jwks": "http://insecure.example.com/jwks",
      },
    });

    expect(await validate(request)).toBeNull();
  });

  test("returns null when dynamic header meta-header is missing", async () => {
    const jwtConfig: JwtValidatorConfig = {
      header: "X-authentik-jwt",
      key_source: { kind: "dynamic_header", meta_header: "X-authentik-meta-jwks" },
    };

    const token = await signJwt({ sub: "user-no-meta" });
    const validate = createJwtValidator(jwtConfig, makeConfig());
    const request = new Request("http://localhost", {
      headers: { "X-authentik-jwt": token },
    });

    expect(await validate(request)).toBeNull();
  });

  test("returns null when ALB region is empty", async () => {
    const jwtConfig: JwtValidatorConfig = {
      header: "x-amzn-oidc-data",
      key_source: { kind: "aws_alb_pem" },
    };

    const token = await signJwt({ sub: "user-alb" });
    const validate = createJwtValidator(jwtConfig, makeConfig({ region: "" }));
    const request = new Request("http://localhost", {
      headers: { "x-amzn-oidc-data": token },
    });

    expect(await validate(request)).toBeNull();
  });
});
