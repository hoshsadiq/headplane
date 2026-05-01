import type { AuthService, Principal } from "~/server/web/auth";
import { findHeadscaleUserBySubject } from "~/server/web/headscale-identity";
import type { User } from "~/types/User";
import log from "~/utils/log";

import type { IdentityResolver, ProxyIdentity } from "./types";

export type { IdentityResolver, ProxyIdentity } from "./types";

export interface ProxyService {
  authenticate(
    request: Request,
    headscaleUsers?: User[],
  ): Promise<{ principal: Principal; cookie: string } | null>;
}

export function createProxyService(
  auth: AuthService,
  identityResolver: IdentityResolver,
  _config?: unknown,
): ProxyService {
  async function authenticate(
    request: Request,
    headscaleUsers?: User[],
  ): Promise<{ principal: Principal; cookie: string } | null> {
    const identity = await identityResolver(request);
    if (!identity) {
      return null;
    }

    const displayName = identity.name ?? identity.email ?? identity.subject;

    const userId = await auth.findOrCreateUser(identity.subject, {
      name: displayName,
      email: identity.email,
    });

    if (headscaleUsers) {
      try {
        const hsUser = findHeadscaleUserBySubject(headscaleUsers, identity.subject, identity.email);
        if (hsUser) {
          await auth.linkHeadscaleUser(userId, hsUser.id);
        }
      } catch (error) {
        log.warn("auth", "Failed to link Headscale user for proxy identity: %s", String(error));
      }
    }

    const cookie = await auth.createProxySession(userId, {
      name: displayName,
      email: identity.email,
    });

    const cookieValue = cookie.split(";")[0];
    const sessionRequest = new Request(request.url, {
      headers: { cookie: cookieValue },
    });
    const principal = await auth.require(sessionRequest);

    return { principal, cookie };
  }

  return { authenticate };
}
