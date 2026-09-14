const { loadEnvConfig } = require("@next/env");
// next.config.js is evaluated outside Next.js's own env-loading runtime, so
// process.env.NEXT_PUBLIC_API_URL is undefined here unless loaded explicitly
// -- confirmed against this pinned Next.js version's own bundled docs
// (node_modules/next/dist/docs/.../environment-variables.md, "Loading
// Environment Variables with @next/env"). Without this, the CSP below
// silently shipped as `connect-src 'self'` with the backend origin missing
// entirely whenever NEXT_PUBLIC_API_URL was set (e.g. the Basic-tier setup
// script's direct-fetch configuration), breaking every API call in the
// browser with a CSP violation while curl/server-side requests worked fine.
loadEnvConfig(process.cwd());

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async headers() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options",        value: "DENY" },
          { key: "X-Content-Type-Options",  value: "nosniff" },
          { key: "Referrer-Policy",         value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy",      value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              // Same-origin is enough when NEXT_PUBLIC_API_URL is unset (the
              // Next.js proxy handles it); when it IS set (direct-fetch
              // deployments like Basic tier's setup-basic.sh), the backend
              // origin must be explicitly allowed here or every API call
              // gets silently blocked by this same policy.
              `connect-src 'self'${apiUrl ? ` ${apiUrl}` : ""}`,
              "img-src 'self' data:",
              "font-src 'self'",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join("; "),
          },
        ],
      },
    ];
  },
};
module.exports = nextConfig;