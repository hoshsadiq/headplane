import { beforeEach, describe, expect, test, vi } from "vitest";

import type { ProxyConfig } from "~/server/config/config-schema";
import {
  createProxyService,
  type IdentityResolver,
  type ProxyIdentity,
} from "~/server/proxy/service";
import type { AuthService } from "~/server/web/auth";
import type { User } from "~/types/User";

import { createTestAuth } from "../auth/create-auth";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

const defaultConfig = { enabled: true } as ProxyConfig;

function makeResolver(identity: ProxyIdentity | null): IdentityResolver {
  return async () => identity;
}

function makeHsUser(overrides: Partial<User> = {}): User {
  return {
    id: "hs-1",
    name: "test",
    createdAt: "2024-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("proxy provisioning", () => {
  let auth: AuthService;

  beforeEach(() => {
    ({ auth } = createTestAuth());
  });

  test("returns null when identity resolver returns null", async () => {
    const service = createProxyService(auth, makeResolver(null), defaultConfig);
    const result = await service.authenticate(new Request("http://localhost"));
    expect(result).toBeNull();
  });

  test("first proxy user becomes owner", async () => {
    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "John", email: "john@test.com" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"));
    expect(result).not.toBeNull();
    expect(result!.principal.kind).toBe("proxy");
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.user.role).toBe("owner");
    }
  });

  test("subsequent proxy users become member", async () => {
    await auth.findOrCreateUser("proxy:authelia:first", { name: "First" });

    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:second", name: "Second" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"));
    expect(result).not.toBeNull();
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.user.role).toBe("member");
    }
  });

  test("repeat request reuses existing user record", async () => {
    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "John" }),
      defaultConfig,
    );

    const result1 = await service.authenticate(new Request("http://localhost"));
    const result2 = await service.authenticate(new Request("http://localhost"));

    expect(result1).not.toBeNull();
    expect(result2).not.toBeNull();
    if (result1!.principal.kind === "proxy" && result2!.principal.kind === "proxy") {
      expect(result1!.principal.user.id).toBe(result2!.principal.user.id);
    }
  });

  test("updates profile on repeat login when changed", async () => {
    const service1 = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "Old Name", email: "old@test.com" }),
      defaultConfig,
    );
    await service1.authenticate(new Request("http://localhost"));

    const service2 = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "New Name", email: "new@test.com" }),
      defaultConfig,
    );
    const result = await service2.authenticate(new Request("http://localhost"));

    expect(result).not.toBeNull();
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.profile.name).toBe("New Name");
      expect(result!.principal.profile.email).toBe("new@test.com");
    }
  });

  test("creates session with proxy kind and valid cookie", async () => {
    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "John" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"));
    expect(result).not.toBeNull();
    expect(result!.principal.kind).toBe("proxy");
    expect(result!.cookie).toContain("_hp_test=");
    expect(result!.cookie).toContain("Max-Age=");
  });

  test("links headscale user via email fallback", async () => {
    const hsUsers: User[] = [
      makeHsUser({ id: "hs-42", email: "john@test.com", provider: "local" }),
    ];

    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "John", email: "john@test.com" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"), hsUsers);
    expect(result).not.toBeNull();
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.user.headscaleUserId).toBe("hs-42");
    }
  });

  test("no headscale link when no email match", async () => {
    const hsUsers: User[] = [
      makeHsUser({ id: "hs-42", email: "other@test.com", provider: "local" }),
    ];

    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "John" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"), hsUsers);
    expect(result).not.toBeNull();
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.user.headscaleUserId).toBeUndefined();
    }
  });

  test("different presets create separate users", async () => {
    const service1 = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", name: "John" }),
      defaultConfig,
    );
    const service2 = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authentik:john-uid", name: "John" }),
      defaultConfig,
    );

    const result1 = await service1.authenticate(new Request("http://localhost"));
    const result2 = await service2.authenticate(new Request("http://localhost"));

    expect(result1).not.toBeNull();
    expect(result2).not.toBeNull();
    if (result1!.principal.kind === "proxy" && result2!.principal.kind === "proxy") {
      expect(result1!.principal.user.id).not.toBe(result2!.principal.user.id);
      expect(result1!.principal.user.subject).toBe("proxy:authelia:john");
      expect(result2!.principal.user.subject).toBe("proxy:authentik:john-uid");
    }
  });

  test("uses email as display name when name not provided", async () => {
    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john", email: "john@test.com" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"));
    expect(result).not.toBeNull();
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.profile.name).toBe("john@test.com");
    }
  });

  test("uses subject as display name when neither name nor email provided", async () => {
    const service = createProxyService(
      auth,
      makeResolver({ subject: "proxy:authelia:john" }),
      defaultConfig,
    );

    const result = await service.authenticate(new Request("http://localhost"));
    expect(result).not.toBeNull();
    if (result!.principal.kind === "proxy") {
      expect(result!.principal.profile.name).toBe("proxy:authelia:john");
    }
  });
});
