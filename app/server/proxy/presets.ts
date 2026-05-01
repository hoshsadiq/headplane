export type ProxyPreset = {
  name: string;
  jwt?: {
    header: string;
    keySource:
      | { kind: "jwks_url"; url: string }
      | { kind: "oidc_discovery" }
      | { kind: "aws_alb_pem"; region: string }
      | { kind: "google_iap" }
      | { kind: "dynamic_header"; metaHeader: string };
  };
  headers: {
    subject: string;
    email?: string;
    name?: string;
  };
};

export const PRESETS: Record<string, ProxyPreset> = {
  authelia: {
    name: "Authelia",
    headers: {
      subject: "Remote-User",
      email: "Remote-Email",
      name: "Remote-Name",
    },
  },
  authentik: {
    name: "Authentik",
    jwt: {
      header: "X-authentik-jwt",
      keySource: {
        kind: "dynamic_header",
        metaHeader: "X-authentik-meta-jwks",
      },
    },
    headers: {
      subject: "X-authentik-uid",
      email: "X-authentik-email",
      name: "X-authentik-name",
    },
  },
  "oauth2-proxy": {
    name: "oauth2-proxy",
    jwt: {
      header: "Authorization",
      keySource: {
        kind: "oidc_discovery",
      },
    },
    headers: {
      subject: "X-Forwarded-Email",
      email: "X-Forwarded-Email",
      name: "X-Forwarded-Preferred-Username",
    },
  },
  alb: {
    name: "AWS ALB",
    jwt: {
      header: "x-amzn-oidc-data",
      keySource: {
        kind: "aws_alb_pem",
        region: "",
      },
    },
    headers: {
      subject: "x-amzn-oidc-identity",
      email: "x-amzn-oidc-identity",
    },
  },
  "cloudflare-access": {
    name: "Cloudflare Access",
    jwt: {
      header: "cf-access-jwt-assertion",
      keySource: {
        kind: "jwks_url",
        url: "https://{team}.cloudflareaccess.com/cdn-cgi/access/certs",
      },
    },
    headers: {
      subject: "Cf-Access-Authenticated-User-Email",
      email: "Cf-Access-Authenticated-User-Email",
    },
  },
  "gcp-iap": {
    name: "GCP IAP",
    jwt: {
      header: "x-goog-iap-jwt-assertion",
      keySource: {
        kind: "google_iap",
      },
    },
    headers: {
      subject: "X-Goog-Authenticated-User-Id",
      email: "X-Goog-Authenticated-User-Email",
    },
  },
};

export type ProxyPresetName = keyof typeof PRESETS;
