import { type } from "arktype";
import { describe, expect, test, vi } from "vitest";

import { headplaneConfig } from "~/server/config/config-schema";
import type { HeadplaneConfig } from "~/server/config/config-schema";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

describe("proxy config schema", () => {
  test("valid config: enabled=true, preset=authelia", () => {
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
        preset: "authelia",
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: enabled=true, preset=alb, region=us-east-1", () => {
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
        preset: "alb",
        region: "us-east-1",
      },
    };

    const result = headplaneConfig(config);
    expect(result).not.toBeInstanceOf(type.errors);
  });

  test("valid config: enabled=true, manual headers without preset", () => {
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
          subject: "X-Remote-User",
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

  test("invalid config: preset is unknown provider", () => {
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
        enabled: true,
        preset: "unknown-provider",
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

  test("valid config: all 6 presets are accepted", () => {
    const presets = [
      "authelia",
      "authentik",
      "oauth2-proxy",
      "alb",
      "cloudflare-access",
      "gcp-iap",
    ] as const;

    for (const preset of presets) {
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
          enabled: true,
          preset,
        },
      };

      const result = headplaneConfig(config);
      expect(result).not.toBeInstanceOf(Error);
    }
  });
});
