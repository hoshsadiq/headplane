import { describe, expect, test, vi } from "vitest";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

import type { ProxyConfig } from "~/server/config/config-schema";
import {
  createIdentityResolver,
  type JwtClaims,
  type JwtValidator,
  type ProxyPresetConfig,
} from "~/server/proxy/identity";

function makeRequest(headers: Record<string, string>): Request {
  return new Request("http://localhost/admin/", { headers });
}

function jwtReturning(claims: JwtClaims): JwtValidator {
  return async () => claims;
}

const jwtReturningNull: JwtValidator = async () => null;

const autheliaPreset: ProxyPresetConfig = {
  key: "authelia",
  headers: { subject: "Remote-User", email: "Remote-Email", name: "Remote-Name" },
};

const authentikPreset: ProxyPresetConfig = {
  key: "authentik",
  headers: { subject: "X-authentik-uid", email: "X-authentik-email", name: "X-authentik-name" },
};

const albPreset: ProxyPresetConfig = {
  key: "alb",
  headers: { subject: "x-amzn-oidc-identity", email: "x-amzn-oidc-identity" },
};

const gcpIapPreset: ProxyPresetConfig = {
  key: "gcp-iap",
  headers: { subject: "X-Goog-Authenticated-User-Id", email: "X-Goog-Authenticated-User-Email" },
};

const baseConfig: ProxyConfig = { enabled: true };

describe("proxy identity resolution", () => {
  test("uses JWT claims when validator returns claims", async () => {
    const resolver = createIdentityResolver(
      authentikPreset,
      baseConfig,
      jwtReturning({ sub: "uid-123", email: "user@example.com", name: "John" }),
    );

    const identity = await resolver(
      makeRequest({
        "X-authentik-uid": "header-uid",
        "X-authentik-email": "header@example.com",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:authentik:uid-123",
      email: "user@example.com",
      name: "John",
    });
  });

  test("falls back to headers when JWT validator returns null", async () => {
    const resolver = createIdentityResolver(authentikPreset, baseConfig, jwtReturningNull);

    const identity = await resolver(
      makeRequest({
        "X-authentik-uid": "uid-456",
        "X-authentik-email": "header@example.com",
        "X-authentik-name": "Jane",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:authentik:uid-456",
      email: "header@example.com",
      name: "Jane",
    });
  });

  test("uses headers directly when no JWT validator provided", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "Remote-User": "john",
        "Remote-Email": "john@example.com",
        "Remote-Name": "John Doe",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:authelia:john",
      email: "john@example.com",
      name: "John Doe",
    });
  });

  test("reads Authelia Remote-* headers correctly", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "Remote-User": "alice",
        "Remote-Email": "alice@corp.com",
        "Remote-Name": "Alice Smith",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:authelia:alice",
      email: "alice@corp.com",
      name: "Alice Smith",
    });
  });

  test("builds identity from Authentik JWT claims", async () => {
    const resolver = createIdentityResolver(
      authentikPreset,
      baseConfig,
      jwtReturning({ sub: "ak-user-id", email: "ak@example.com", name: "AK User" }),
    );

    const identity = await resolver(makeRequest({}));

    expect(identity).toEqual({
      subject: "proxy:authentik:ak-user-id",
      email: "ak@example.com",
      name: "AK User",
    });
  });

  test("builds identity from ALB JWT claims", async () => {
    const resolver = createIdentityResolver(
      albPreset,
      baseConfig,
      jwtReturning({ sub: "alb-sub", email: "alb@example.com" }),
    );

    const identity = await resolver(makeRequest({}));

    expect(identity).toEqual({
      subject: "proxy:alb:alb-sub",
      email: "alb@example.com",
      name: undefined,
    });
  });

  test("strips accounts.google.com: prefix from GCP IAP JWT email", async () => {
    const resolver = createIdentityResolver(
      gcpIapPreset,
      baseConfig,
      jwtReturning({ sub: "123456", email: "accounts.google.com:user@gmail.com" }),
    );

    const identity = await resolver(makeRequest({}));

    expect(identity).toEqual({
      subject: "proxy:gcp-iap:123456",
      email: "user@gmail.com",
      name: undefined,
    });
  });

  test("strips accounts.google.com: prefix from GCP IAP header email", async () => {
    const resolver = createIdentityResolver(gcpIapPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "X-Goog-Authenticated-User-Id": "accounts.google.com:123456",
        "X-Goog-Authenticated-User-Email": "accounts.google.com:user@gmail.com",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:gcp-iap:accounts.google.com:123456",
      email: "user@gmail.com",
      name: undefined,
    });
  });

  test("uses overridden headers when manual config provided", async () => {
    const overriddenPreset: ProxyPresetConfig = {
      key: "authelia",
      headers: { subject: "X-Custom-User", email: "X-Custom-Email" },
    };

    const resolver = createIdentityResolver(overriddenPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "Remote-User": "should-be-ignored",
        "X-Custom-User": "custom-user",
        "X-Custom-Email": "custom@example.com",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:authelia:custom-user",
      email: "custom@example.com",
      name: undefined,
    });
  });

  test("uses custom key for manual config without preset", async () => {
    const customPreset: ProxyPresetConfig = {
      key: "custom",
      headers: { subject: "X-Remote-User", email: "X-Remote-Email" },
    };

    const resolver = createIdentityResolver(customPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "X-Remote-User": "bob",
        "X-Remote-Email": "bob@corp.com",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:custom:bob",
      email: "bob@corp.com",
      name: undefined,
    });
  });

  test("returns null when no subject found", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "Remote-Email": "orphan@example.com",
      }),
    );

    expect(identity).toBeNull();
  });

  test("returns null when subject header is empty string", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);

    const identity = await resolver(makeRequest({ "Remote-User": "" }));

    expect(identity).toBeNull();
  });

  test("reads headers case-insensitively", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "remote-user": "case-test",
        "REMOTE-EMAIL": "case@test.com",
      }),
    );

    expect(identity).toEqual({
      subject: "proxy:authelia:case-test",
      email: "case@test.com",
      name: undefined,
    });
  });

  test("prefixes subject with proxy:{preset}:{value}", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);
    const identity = await resolver(makeRequest({ "Remote-User": "testuser" }));

    expect(identity?.subject).toBe("proxy:authelia:testuser");
  });

  test("returns identity without email or name when only subject present", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);
    const identity = await resolver(makeRequest({ "Remote-User": "minimal" }));

    expect(identity).toEqual({
      subject: "proxy:authelia:minimal",
      email: undefined,
      name: undefined,
    });
  });

  test("returns null when JWT has no sub and no header subject", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig, jwtReturningNull);
    const identity = await resolver(makeRequest({}));

    expect(identity).toBeNull();
  });
});

describe("proxy IP whitelist", () => {
  test("allows request when IP matches allowed list", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.1"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "10.0.0.1",
        "Remote-User": "allowed",
      }),
    );

    expect(identity).not.toBeNull();
    expect(identity?.subject).toBe("proxy:authelia:allowed");
  });

  test("blocks request when IP is not in allowed list", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.1"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "192.168.1.1",
        "Remote-User": "blocked",
      }),
    );

    expect(identity).toBeNull();
  });

  test("allows request when IP is in CIDR range", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.0/8"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "10.1.2.3",
        "Remote-User": "cidr-user",
      }),
    );

    expect(identity).not.toBeNull();
    expect(identity?.subject).toBe("proxy:authelia:cidr-user");
  });

  test("blocks request when IP is outside CIDR range", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.0/8"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "192.168.1.1",
        "Remote-User": "outside-cidr",
      }),
    );

    expect(identity).toBeNull();
  });

  test("allows all IPs when no whitelist configured", async () => {
    const resolver = createIdentityResolver(autheliaPreset, baseConfig);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "192.168.1.1",
        "Remote-User": "any-ip",
      }),
    );

    expect(identity).not.toBeNull();
  });

  test("allows all IPs when allowed_ips is empty array", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: [] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "192.168.1.1",
        "Remote-User": "empty-list",
      }),
    );

    expect(identity).not.toBeNull();
  });

  test("uses X-Real-IP when X-Forwarded-For absent", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.1"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Real-IP": "10.0.0.1",
        "Remote-User": "real-ip",
      }),
    );

    expect(identity).not.toBeNull();
  });

  test("blocks request when no IP headers and whitelist configured", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.0/8"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(makeRequest({ "Remote-User": "no-ip" }));

    expect(identity).toBeNull();
  });

  test("takes first IP from X-Forwarded-For chain", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.1"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const identity = await resolver(
      makeRequest({
        "X-Forwarded-For": "10.0.0.1, 172.16.0.1, 192.168.0.1",
        "Remote-User": "chain",
      }),
    );

    expect(identity).not.toBeNull();
  });

  test("supports /32 CIDR for exact match", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.5/32"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const allowed = await resolver(
      makeRequest({ "X-Forwarded-For": "10.0.0.5", "Remote-User": "exact" }),
    );
    expect(allowed).not.toBeNull();

    const blocked = await resolver(
      makeRequest({ "X-Forwarded-For": "10.0.0.6", "Remote-User": "near" }),
    );
    expect(blocked).toBeNull();
  });

  test("supports multiple allowed ranges", async () => {
    const config: ProxyConfig = {
      enabled: true,
      allowed_ips: ["10.0.0.0/8", "172.16.0.0/12"],
    };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const fromTen = await resolver(
      makeRequest({ "X-Forwarded-For": "10.5.5.5", "Remote-User": "ten" }),
    );
    expect(fromTen).not.toBeNull();

    const fromSeventeen = await resolver(
      makeRequest({ "X-Forwarded-For": "172.20.1.1", "Remote-User": "seventeen" }),
    );
    expect(fromSeventeen).not.toBeNull();

    const fromPublic = await resolver(
      makeRequest({ "X-Forwarded-For": "8.8.8.8", "Remote-User": "public" }),
    );
    expect(fromPublic).toBeNull();
  });

  test("IPv6 address is not matched by IPv4 CIDR range", async () => {
    const config: ProxyConfig = { enabled: true, allowed_ips: ["10.0.0.0/8"] };
    const resolver = createIdentityResolver(autheliaPreset, config);

    const loopback = await resolver(
      makeRequest({ "X-Forwarded-For": "::1", "Remote-User": "ipv6-loopback" }),
    );
    expect(loopback).toBeNull();

    const full = await resolver(
      makeRequest({ "X-Forwarded-For": "2001:db8::1", "Remote-User": "ipv6-full" }),
    );
    expect(full).toBeNull();
  });
});
