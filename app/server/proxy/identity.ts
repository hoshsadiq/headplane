import type { ProxyConfig } from "~/server/config/config-schema";
import log from "~/utils/log";

import { GCP_IAP_EMAIL_PREFIX } from "./types";
import type { JwtClaims, JwtValidator, ProxyIdentity, ProxyPresetConfig } from "./types";

export type { JwtClaims, JwtValidator, ProxyIdentity, ProxyPresetConfig } from "./types";

function getClientIp(request: Request): string | null {
  const forwarded = request.headers.get("X-Forwarded-For");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }

  const realIp = request.headers.get("X-Real-IP");
  if (realIp) return realIp.trim();

  return null;
}

function ipv4ToNumber(ip: string): number {
  const parts = ip.split(".");
  return (
    ((Number.parseInt(parts[0]) << 24) |
      (Number.parseInt(parts[1]) << 16) |
      (Number.parseInt(parts[2]) << 8) |
      Number.parseInt(parts[3])) >>>
    0
  );
}

function isIpv4(ip: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

function isIpInRange(ip: string, range: string): boolean {
  const slashIndex = range.indexOf("/");
  const network = slashIndex === -1 ? range : range.substring(0, slashIndex);

  if (!isIpv4(ip) || !isIpv4(network)) return false;

  if (slashIndex === -1) return ip === range;

  const prefix = Number.parseInt(range.substring(slashIndex + 1), 10);
  const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
  return (ipv4ToNumber(ip) & mask) === (ipv4ToNumber(network) & mask);
}

function isIpAllowed(ip: string, allowedRanges: string[]): boolean {
  return allowedRanges.some((range) => isIpInRange(ip, range));
}

function getNonEmptyHeader(request: Request, name: string): string | null {
  const value = request.headers.get(name);
  if (!value || value.trim() === "") return null;
  return value;
}

function stripGcpIapEmailPrefix(email: string): string {
  if (email.startsWith(GCP_IAP_EMAIL_PREFIX)) {
    return email.substring(GCP_IAP_EMAIL_PREFIX.length);
  }
  return email;
}

export function createIdentityResolver(
  preset: ProxyPresetConfig,
  config: ProxyConfig,
  jwtValidator?: JwtValidator,
): (request: Request) => Promise<ProxyIdentity | null> {
  return async (request: Request): Promise<ProxyIdentity | null> => {
    if (config.allowed_ips?.length) {
      const clientIp = getClientIp(request);
      if (!clientIp || !isIpAllowed(clientIp, config.allowed_ips)) {
        log.debug("auth", "proxy request rejected: client IP not in allowed ranges");
        return null;
      }
    }

    if (jwtValidator) {
      const claims = await jwtValidator(request);
      if (claims) {
        let email = claims.email;
        if (email && preset.key === "gcp-iap") {
          email = stripGcpIapEmailPrefix(email);
        }

        return {
          subject: `proxy:${preset.key}:${claims.sub}`,
          email,
          name: claims.name,
        };
      }
    }

    const rawSubject = getNonEmptyHeader(request, preset.headers.subject);
    if (!rawSubject) return null;

    let email: string | undefined;
    if (preset.headers.email) {
      const rawEmail = getNonEmptyHeader(request, preset.headers.email);
      if (rawEmail) {
        email = preset.key === "gcp-iap" ? stripGcpIapEmailPrefix(rawEmail) : rawEmail;
      }
    }

    let name: string | undefined;
    if (preset.headers.name) {
      const rawName = getNonEmptyHeader(request, preset.headers.name);
      if (rawName) name = rawName;
    }

    return {
      subject: `proxy:${preset.key}:${rawSubject}`,
      email,
      name,
    };
  };
}
