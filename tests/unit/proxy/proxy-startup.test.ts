import { beforeEach, describe, expect, test, vi } from "vitest";

import type { HeadplaneConfig } from "~/server/config/config-schema";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

import log from "~/utils/log";

const baseConfig: HeadplaneConfig = {
  debug: false,
  server: {
    host: "0.0.0.0",
    port: 3000,
    data_path: "/tmp/test",
    cookie_secret: "12345678901234567890123456789012",
    cookie_secure: true,
    cookie_max_age: 86400,
  },
  headscale: {
    url: "http://localhost:8080",
    config_strict: true,
  },
};

// Simulate the validation logic from context.ts
function validateProxyStartup(config: HeadplaneConfig, headscaleApiKey: string | undefined) {
  if (config.proxy?.enabled !== false) {
    if (!headscaleApiKey) {
      log.error("auth", "proxy auth enabled but headscale.api_key is not configured");
    }
    if (!config.proxy?.allowed_ips?.length) {
      log.warn(
        "auth",
        "proxy auth enabled without allowed_ips: any request can forge proxy headers",
      );
    }
  }
}

describe("proxy startup validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("proxy enabled without allowed_ips logs warning", () => {
    const config: HeadplaneConfig = {
      ...baseConfig,
      headscale: {
        ...baseConfig.headscale,
        api_key: "test-key",
      },
      proxy: {
        enabled: true,
        headers: { subject: "Remote-User" },
      },
    };

    validateProxyStartup(config, config.headscale.api_key);

    expect(log.warn).toHaveBeenCalledWith(
      "auth",
      "proxy auth enabled without allowed_ips: any request can forge proxy headers",
    );
  });

  test("proxy enabled without headscaleApiKey logs error", () => {
    const config: HeadplaneConfig = {
      ...baseConfig,
      proxy: {
        enabled: true,
        headers: { subject: "Remote-User" },
        allowed_ips: ["10.0.0.0/8"],
      },
    };

    validateProxyStartup(config, undefined);

    expect(log.error).toHaveBeenCalledWith(
      "auth",
      "proxy auth enabled but headscale.api_key is not configured",
    );
  });

  test("proxy disabled does not log warnings or errors", () => {
    const config: HeadplaneConfig = {
      ...baseConfig,
      proxy: {
        enabled: false,
        headers: { subject: "Remote-User" },
      },
    };

    validateProxyStartup(config, undefined);

    expect(log.warn).not.toHaveBeenCalled();
    expect(log.error).not.toHaveBeenCalled();
  });

  test("proxy enabled with both configured does not log warnings or errors", () => {
    const config: HeadplaneConfig = {
      ...baseConfig,
      headscale: {
        ...baseConfig.headscale,
        api_key: "test-key",
      },
      proxy: {
        enabled: true,
        headers: { subject: "Remote-User" },
        allowed_ips: ["10.0.0.0/8"],
      },
    };

    validateProxyStartup(config, config.headscale.api_key);

    expect(log.warn).not.toHaveBeenCalled();
    expect(log.error).not.toHaveBeenCalled();
  });
});
