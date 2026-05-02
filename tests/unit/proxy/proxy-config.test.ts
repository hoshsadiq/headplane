import { type } from "arktype";
import { describe, expect, test, vi } from "vitest";

import { headplaneConfig } from "~/server/config/config-schema";
import type { HeadplaneConfig } from "~/server/config/config-schema";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

describe("proxy config schema", () => {
  test("valid config: headers only (no jwt)", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: true,
        headers: {
          subject: "Remote-User",
          email: "Remote-Email",
          name: "Remote-Name",
        },
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: headers + jwt with jwks_url key source", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: true,
        headers: {
          subject: "Cf-Access-Authenticated-User-Email",
          email: "Cf-Access-Authenticated-User-Email",
        },
        jwt: {
          header: "Cf-Access-Jwt-Assertion",
          key_source: {
            kind: "jwks_url",
            url: "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs",
          },
        },
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: headers + jwt with dynamic_header key source", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: true,
        headers: {
          subject: "X-authentik-uid",
          email: "X-authentik-email",
        },
        jwt: {
          header: "X-authentik-jwt",
          key_source: {
            kind: "dynamic_header",
            meta_header: "X-authentik-meta-jwks",
          },
        },
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: headers + jwt with oidc_discovery key source", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: true,
        issuer: "https://your-idp.example.com",
        headers: {
          subject: "X-Forwarded-Email",
          email: "X-Forwarded-Email",
        },
        jwt: {
          header: "Authorization",
          key_source: { kind: "oidc_discovery" },
        },
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: headers + jwt with aws_alb_pem key source", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: true,
        region: "us-east-1",
        headers: {
          subject: "x-amzn-oidc-identity",
          email: "x-amzn-oidc-identity",
        },
        jwt: {
          header: "x-amzn-oidc-data",
          key_source: { kind: "aws_alb_pem" },
        },
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: headers + jwt with google_iap key source", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: true,
        audience: "/projects/123/global/backendServices/456",
        headers: {
          subject: "X-Goog-Authenticated-User-Id",
          email: "X-Goog-Authenticated-User-Email",
        },
        jwt: {
          header: "X-Goog-Iap-Jwt-Assertion",
          key_source: { kind: "google_iap" },
        },
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("invalid config: enabled is string instead of boolean", () => {
    const config = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
      proxy: {
        enabled: "yes",
      },
    };

    const result = headplaneConfig(config);
    expect(result).toBeInstanceOf(type.errors);
  });

  test("proxy absent from config still validates", () => {
    const config: HeadplaneConfig = {
      debug: false,
      server: {
        host: "0.0.0.0",
        port: 3000,
        data_path: "/var/lib/headplane/",
        cookie_secret: "12345678901234567890123456789012",
        cookie_secure: true,
        cookie_max_age: 86400,
      },
      headscale: {
        url: "http://localhost:8080",
        config_strict: true,
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });
});
