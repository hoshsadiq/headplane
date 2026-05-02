import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { users } from "~/server/db/schema";
import type { ProxyService } from "~/server/proxy/service";
import type { AuthService, Principal } from "~/server/web/auth";

import { createTestAuth } from "../auth/create-auth";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

import log from "~/utils/log";

function makeProxyPrincipal(subject: string, name: string, email?: string): Principal {
  return {
    kind: "proxy",
    sessionId: "mock-sid",
    user: { id: "mock-uid", subject, role: "member", headscaleUserId: undefined },
    profile: { name, email },
  };
}

describe("proxy resolve integration", () => {
  let auth: AuthService;
  let mockAuthenticate: ReturnType<typeof vi.fn>;
  let proxyService: ProxyService;

  beforeEach(() => {
    const ctx = createTestAuth();
    auth = ctx.auth;
    mockAuthenticate = vi.fn();
    proxyService = { authenticate: mockAuthenticate } as unknown as ProxyService;
    vi.mocked(log.warn).mockClear();
  });

  test("proxy headers present + proxy enabled returns proxy principal", async () => {
    auth.setProxyService(proxyService);
    const expected = makeProxyPrincipal("proxy:authelia:alice", "Alice", "alice@test.com");
    mockAuthenticate.mockResolvedValue({
      principal: expected,
      cookie: "_hp_test=xyz; Path=/admin/; HttpOnly",
    });

    const request = new Request("http://localhost/test", {
      headers: { "Remote-User": "alice" },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("proxy");
    if (result.kind === "proxy") {
      expect(result.user.subject).toBe("proxy:authelia:alice");
      expect(result.profile.name).toBe("Alice");
    }
    expect(mockAuthenticate).toHaveBeenCalledOnce();
    expect(auth.getProxyCookie(request)).toBe("_hp_test=xyz; Path=/admin/; HttpOnly");
  });

  test("valid JWT present returns principal from JWT claims", async () => {
    auth.setProxyService(proxyService);
    const expected = makeProxyPrincipal("proxy:authentik:jwt-sub", "JWT User", "jwt@test.com");
    mockAuthenticate.mockResolvedValue({
      principal: expected,
      cookie: "_hp_test=jwt; Path=/admin/; HttpOnly",
    });

    const request = new Request("http://localhost/test", {
      headers: { "X-authentik-jwt": "eyJhbGciOi...", "X-authentik-uid": "jwt-sub" },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("proxy");
    if (result.kind === "proxy") {
      expect(result.user.subject).toBe("proxy:authentik:jwt-sub");
    }
  });

  test("invalid JWT + valid headers returns principal from header fallback", async () => {
    auth.setProxyService(proxyService);
    const expected = makeProxyPrincipal("proxy:authentik:hdr-user", "Header User");
    mockAuthenticate.mockResolvedValue({
      principal: expected,
      cookie: "_hp_test=hdr; Path=/admin/; HttpOnly",
    });

    const request = new Request("http://localhost/test", {
      headers: { "X-authentik-jwt": "invalid-jwt", "X-authentik-uid": "hdr-user" },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("proxy");
    if (result.kind === "proxy") {
      expect(result.user.subject).toBe("proxy:authentik:hdr-user");
    }
  });

  test("proxy headers present + proxy disabled falls through to cookie auth", async () => {
    const userId = await auth.findOrCreateUser("sub-oidc", { name: "OIDC User" });
    const cookie = await auth.createOidcSession(userId, { name: "OIDC User" });
    const cookieValue = cookie.split(";")[0];

    const request = new Request("http://localhost/test", {
      headers: { "Remote-User": "alice", cookie: cookieValue },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("oidc");
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  test("no proxy headers + proxy enabled falls through to cookie auth", async () => {
    auth.setProxyService(proxyService);
    mockAuthenticate.mockResolvedValue(null);

    const userId = await auth.findOrCreateUser("sub-oidc", { name: "OIDC User" });
    const cookie = await auth.createOidcSession(userId, { name: "OIDC User" });
    const cookieValue = cookie.split(";")[0];

    const request = new Request("http://localhost/test", {
      headers: { cookie: cookieValue },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("oidc");
  });

  test("proxy headers + valid proxy session cookie reuses session", async () => {
    auth.setProxyService(proxyService);

    const userId = await auth.findOrCreateUser("proxy:test:alice", { name: "Alice" });
    const cookie = await auth.createProxySession(userId, { name: "Alice" });
    const cookieValue = cookie.split(";")[0];

    const request = new Request("http://localhost/test", {
      headers: { "Remote-User": "alice", cookie: cookieValue },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("proxy");
    if (result.kind === "proxy") {
      expect(result.user.subject).toBe("proxy:test:alice");
    }
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  test("proxy headers + session cookie for different user provisions new", async () => {
    auth.setProxyService(proxyService);

    const userA = await auth.findOrCreateUser("sub-oidc-a", { name: "User A" });
    const cookie = await auth.createOidcSession(userA, { name: "User A" });
    const cookieValue = cookie.split(";")[0];

    const newPrincipal = makeProxyPrincipal("proxy:authelia:user-b", "User B");
    mockAuthenticate.mockResolvedValue({
      principal: newPrincipal,
      cookie: "_hp_test=new; Path=/admin/; HttpOnly",
    });

    const request = new Request("http://localhost/test", {
      headers: { "Remote-User": "user-b", cookie: cookieValue },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("proxy");
    if (result.kind === "proxy") {
      expect(result.user.subject).toBe("proxy:authelia:user-b");
    }
    expect(mockAuthenticate).toHaveBeenCalledOnce();
  });

  test("proxy headers but IP blocked falls through to cookie auth", async () => {
    auth.setProxyService(proxyService);
    mockAuthenticate.mockResolvedValue(null);

    const userId = await auth.findOrCreateUser("sub-oidc", { name: "OIDC User" });
    const cookie = await auth.createOidcSession(userId, { name: "OIDC User" });
    const cookieValue = cookie.split(";")[0];

    const request = new Request("http://localhost/test", {
      headers: {
        "Remote-User": "blocked-user",
        "X-Forwarded-For": "10.0.0.99",
        cookie: cookieValue,
      },
    });
    const result = await auth.require(request);
    expect(result.kind).toBe("oidc");
    expect(mockAuthenticate).toHaveBeenCalledOnce();
  });

  test("all three auth kinds coexist", async () => {
    auth.setProxyService(proxyService);

    const oidcUser = await auth.findOrCreateUser("sub-oidc", { name: "OIDC User" });
    const oidcCookie = await auth.createOidcSession(oidcUser, { name: "OIDC User" });
    const oidcCookieVal = oidcCookie.split(";")[0];

    const apiKeyCookie = await auth.createApiKeySession("test-api-key", "Test Key", 3600_000);
    const apiKeyCookieVal = apiKeyCookie.split(";")[0];

    const proxyUser = await auth.findOrCreateUser("proxy:test:puser", { name: "Proxy User" });
    const proxyCookie = await auth.createProxySession(proxyUser, { name: "Proxy User" });
    const proxyCookieVal = proxyCookie.split(";")[0];

    mockAuthenticate.mockResolvedValue(null);
    const oidcReq = new Request("http://localhost/a", { headers: { cookie: oidcCookieVal } });
    expect((await auth.require(oidcReq)).kind).toBe("oidc");

    mockAuthenticate.mockResolvedValue(null);
    const apiKeyReq = new Request("http://localhost/b", { headers: { cookie: apiKeyCookieVal } });
    expect((await auth.require(apiKeyReq)).kind).toBe("api_key");

    const proxyReq = new Request("http://localhost/c", {
      headers: { "Remote-User": "puser", cookie: proxyCookieVal },
    });
    expect((await auth.require(proxyReq)).kind).toBe("proxy");
  });

  test("proxy disabled + auth-specific header logs one-time warning", async () => {
    const userId = await auth.findOrCreateUser("sub-1", { name: "User" });
    const cookie = await auth.createOidcSession(userId, { name: "User" });
    const cookieValue = cookie.split(";")[0];

    const req1 = new Request("http://localhost/test1", {
      headers: { "Remote-User": "alice", cookie: cookieValue },
    });
    await auth.require(req1);

    expect(vi.mocked(log.warn)).toHaveBeenCalledWith(
      "auth",
      expect.stringContaining("remote-user"),
    );
    const warnCount = vi.mocked(log.warn).mock.calls.length;

    const req2 = new Request("http://localhost/test2", {
      headers: { "Remote-User": "bob", cookie: cookieValue },
    });
    await auth.require(req2);
    expect(vi.mocked(log.warn).mock.calls.length).toBe(warnCount);
  });

  test("DB error in resolveFromCookie propagates when proxy is enabled", async () => {
    const { auth: testAuth, db: testDb } = createTestAuth();
    const testMockAuthenticate = vi.fn();
    const testProxyService = { authenticate: testMockAuthenticate } as unknown as ProxyService;
    testAuth.setProxyService(testProxyService);
    testMockAuthenticate.mockResolvedValue(null);

    const userId = await testAuth.findOrCreateUser("proxy:test:dbfail", { name: "DB Fail" });
    const cookie = await testAuth.createProxySession(userId, { name: "DB Fail" });
    const cookieValue = cookie.split(";")[0];

    await testDb.delete(users).where(eq(users.id, userId));

    const request = new Request("http://localhost/test", {
      headers: {
        "Remote-User": "dbfail",
        cookie: cookieValue,
      },
    });

    await expect(testAuth.require(request)).rejects.toThrow("User record not found");
  });

  test("proxy disabled + generic header X-Forwarded-User produces no warning", async () => {
    const userId = await auth.findOrCreateUser("sub-1", { name: "User" });
    const cookie = await auth.createOidcSession(userId, { name: "User" });
    const cookieValue = cookie.split(";")[0];

    const request = new Request("http://localhost/test", {
      headers: { "X-Forwarded-User": "alice", cookie: cookieValue },
    });
    await auth.require(request);

    const proxyWarnings = vi
      .mocked(log.warn)
      .mock.calls.filter(
        (c) => typeof c[1] === "string" && c[1].toLowerCase().includes("x-forwarded-user"),
      );
    expect(proxyWarnings).toHaveLength(0);
  });
});
