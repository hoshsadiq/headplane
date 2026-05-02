import { Outlet, data, redirect, type ShouldRevalidateFunction } from "react-router";

import { ErrorBanner } from "~/components/error-banner";
import StatusBanner from "~/components/status-banner";
import { isDataUnauthorizedError } from "~/server/headscale/api/error-client";
import { usersResource } from "~/server/headscale/live-store";
import { Capabilities } from "~/server/web/roles";
import log from "~/utils/log";

import type { Route } from "./+types/app";
import Footer from "./footer";
import Header from "./header";

export const shouldRevalidate: ShouldRevalidateFunction = ({
  currentUrl,
  nextUrl,
  formAction,
  defaultShouldRevalidate,
}) => {
  if (formAction) {
    return defaultShouldRevalidate;
  }

  // Allow programmatic revalidations (e.g. SSE-triggered) where the URL hasn't changed
  if (currentUrl.href === nextUrl.href) {
    return defaultShouldRevalidate;
  }

  return false;
};

export async function loader({ request, context }: Route.LoaderArgs) {
  try {
    const principal = await context.auth.require(request);

    const apiKey = context.auth.getHeadscaleApiKey(principal);
    const api = context.hsApi.getRuntimeClient(apiKey);

    let user;
    if (principal.kind === "api_key") {
      user = { name: principal.displayName, subject: "api_key" };
    } else {
      user = {
        email: principal.profile.email,
        name: principal.profile.name,
        subject: principal.user.subject,
        ...(principal.kind === "oidc"
          ? { picture: principal.profile.picture, username: principal.profile.username }
          : {}),
      };
    }

    // MARK: The session should stay valid if Headscale isn't healthy
    const isHealthy = await api.isHealthy();
    if (isHealthy) {
      try {
        await api.getApiKeys();
      } catch (error) {
        if (isDataUnauthorizedError(error)) {
          const displayName =
            principal.kind === "api_key" ? principal.displayName : principal.profile.name;
          log.warn("auth", "Logging out %s due to expired API key", displayName);
          return redirect("/login", {
            headers: {
              "Set-Cookie": await context.auth.destroySession(request),
            },
          });
        }
      }

      // Self-heal: if the linked Headscale user was deleted, clear the
      // stale link so the user gets prompted to re-link.
      if (
        (principal.kind === "oidc" || principal.kind === "proxy") &&
        principal.user.headscaleUserId
      ) {
        try {
          const usersSnap = await context.hsLive.get(usersResource, api);
          if (!usersSnap.data.some((u) => u.id === principal.user.headscaleUserId)) {
            await context.auth.unlinkHeadscaleUser(principal.user.id);
          }
        } catch {
          // API call failed, skip validation
        }
      }

      // Initial Headscale linking for proxy users (proxy auth can't link at
      // authentication time because headscaleUsers aren't available yet)
      if (
        (principal.kind === "oidc" || principal.kind === "proxy") &&
        !principal.user.headscaleUserId
      ) {
        try {
          const usersSnap = await context.hsLive.get(usersResource, api);
          const { findHeadscaleUserBySubject } = await import("~/server/web/headscale-identity");
          const hsUser = findHeadscaleUserBySubject(
            usersSnap.data,
            principal.user.subject,
            principal.kind === "proxy" ? principal.profile.email : principal.profile.email,
          );
          if (hsUser) {
            await context.auth.linkHeadscaleUser(principal.user.id, hsUser.id);
          }
        } catch {
          // Best-effort linking, don't block the page load
        }
      }
    }

    const proxyCookie = context.auth.getProxyCookie(request);
    const result = {
      access: {
        dns: context.auth.can(principal, Capabilities.read_network),
        machines: context.auth.can(principal, Capabilities.read_machines),
        policy: context.auth.can(principal, Capabilities.read_policy),
        settings: context.auth.can(principal, Capabilities.read_feature),
        ui: context.auth.can(principal, Capabilities.ui_access),
        users: context.auth.can(principal, Capabilities.read_users),
      },
      baseUrl: context.config.headscale.public_url ?? context.config.headscale.url,
      configAvailable: context.hs.readable(),
      isDebug: context.config.debug,
      isHealthy,
      user,
    };
    if (proxyCookie) {
      return data(result, { headers: { "Set-Cookie": proxyCookie } });
    }
    return result;
  } catch {
    return redirect("/login", {
      headers: {
        "Set-Cookie": await context.auth.destroySession(request),
      },
    });
  }
}

export default function AppLayout({ loaderData }: Route.ComponentProps) {
  return (
    <>
      <Header
        access={loaderData.access}
        configAvailable={loaderData.configAvailable}
        user={loaderData.user}
      />
      <main className="container mt-4 mb-24 overscroll-contain">
        {!loaderData.isHealthy && (
          <StatusBanner
            className="mb-4"
            dismissable={false}
            title="Headscale Unreachable"
            variant="critical"
          >
            Unable to connect to the Headscale server. Data shown may be stale and changes cannot be
            saved until the connection is restored.
          </StatusBanner>
        )}
        <Outlet />
      </main>
      <Footer isDebug={loaderData.isDebug} baseUrl={loaderData.baseUrl} />
    </>
  );
}

export function ErrorBoundary({ error }: Route.ErrorBoundaryProps) {
  return (
    <div className="mx-auto my-24 w-fit overscroll-contain">
      <ErrorBanner className="max-w-2xl" error={error} />
    </div>
  );
}
