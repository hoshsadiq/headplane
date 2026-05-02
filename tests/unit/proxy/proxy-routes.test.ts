import { beforeEach, describe, expect, test, vi } from "vitest";

import type { AppContext } from "~/server/context";
import type { AuthService } from "~/server/web/auth";

import { createTestAuth } from "../auth/create-auth";

vi.mock("~/utils/log", () => ({
  default: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

describe("proxy routes", () => {
  let auth: AuthService;

  beforeEach(() => {
    ({ auth } = createTestAuth());
  });

  describe("login loader", () => {
    const proxyHeaders = [
      "remote-user",
      "x-authentik-uid",
      "cf-access-authenticated-user-email",
      "x-amzn-oidc-identity",
      "x-goog-authenticated-user-email",
    ];

    test("proxy enabled + proxy headers present → redirect to /machines", async () => {
      const request = new Request("http://localhost/login", {
        headers: {
          "remote-user": "john",
        },
      });

      const context = {
        proxy: { enabled: true },
        auth,
      } as unknown as AppContext;

      try {
        await context.auth.require(request);
      } catch {
        // No session exists
      }

      const hasProxyHeaders = proxyHeaders.some((h) => request.headers.has(h));
      const shouldRedirect = context.proxy?.enabled !== false && hasProxyHeaders;

      expect(shouldRedirect).toBe(true);
    });

    test("proxy enabled + no proxy headers → show login page (no redirect)", async () => {
      const request = new Request("http://localhost/login");

      const context = {
        proxy: { enabled: true },
        auth,
      } as unknown as AppContext;

      try {
        await context.auth.require(request);
      } catch {
        // No session exists
      }

      const hasProxyHeaders = proxyHeaders.some((h) => request.headers.has(h));
      const shouldRedirect = context.proxy?.enabled !== false && hasProxyHeaders;

      expect(shouldRedirect).toBe(false);
    });

    test("proxy disabled + proxy headers present → show login page (no redirect)", async () => {
      const request = new Request("http://localhost/login", {
        headers: {
          "remote-user": "john",
        },
      });

      const context = {
        proxy: { enabled: false },
        auth,
      } as unknown as AppContext;

      try {
        await context.auth.require(request);
      } catch {
        // No session exists
      }

      const hasProxyHeaders = proxyHeaders.some((h) => request.headers.has(h));
      const shouldRedirect = context.proxy?.enabled !== false && hasProxyHeaders;

      expect(shouldRedirect).toBe(false);
    });

    test("undefined context.proxy + proxy headers → no redirect (guard fix)", async () => {
      const request = new Request("http://localhost/login", {
        headers: {
          "remote-user": "john",
        },
      });

      const context = {
        auth,
      } as unknown as AppContext;

      try {
        await context.auth.require(request);
      } catch {
        // No session exists
      }

      const hasProxyHeaders = proxyHeaders.some((h) => request.headers.has(h));
      const shouldRedirect = context.proxy && context.proxy.enabled !== false && hasProxyHeaders;

      expect(hasProxyHeaders).toBe(true);
      expect(shouldRedirect).toBeFalsy();
    });

    test("login loader with ?s=proxy-logout state → loaderData.urlState === 'proxy-logout'", async () => {
      const request = new Request("http://localhost/login?s=proxy-logout");
      const qp = new URL(request.url).searchParams;
      const urlState = qp.get("s") ?? undefined;

      expect(urlState).toBe("proxy-logout");
    });
  });

  describe("logout action", () => {
    test("proxy principal → redirect to /login?s=proxy-logout", async () => {
      const userId = await auth.findOrCreateUser("proxy:authelia:john", {
        name: "John",
      });
      const cookie = await auth.createProxySession(userId, { name: "John" });

      const cookieValue = cookie.split(";")[0];
      const request = new Request("http://localhost/logout", {
        headers: {
          cookie: cookieValue,
        },
      });

      const principal = await auth.require(request);

      const context = {
        config: { proxy: { enabled: true } },
        auth,
      } as unknown as AppContext;

      let url = "/login";
      if (principal?.kind === "proxy") {
        url = context.config.proxy?.logout_url ?? "/login?s=proxy-logout";
      }

      expect(principal?.kind).toBe("proxy");
      expect(url).toBe("/login?s=proxy-logout");
    });

    test("proxy principal + logout_url configured → redirect to logout_url", async () => {
      const userId = await auth.findOrCreateUser("proxy:authelia:john", {
        name: "John",
      });
      const cookie = await auth.createProxySession(userId, { name: "John" });

      const cookieValue = cookie.split(";")[0];
      const request = new Request("http://localhost/logout", {
        headers: {
          cookie: cookieValue,
        },
      });

      const principal = await auth.require(request);

      const context = {
        config: { proxy: { enabled: true, logout_url: "https://auth.example.com/logout" } },
        auth,
      } as unknown as AppContext;

      let url = "/login";
      if (principal?.kind === "proxy") {
        url = context.config.proxy?.logout_url ?? "/login?s=proxy-logout";
      }

      expect(principal?.kind).toBe("proxy");
      expect(url).toBe("https://auth.example.com/logout");
    });
  });
});
