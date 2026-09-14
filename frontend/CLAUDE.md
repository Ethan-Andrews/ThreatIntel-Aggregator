# Next.js Security Rules

Source: https://github.com/TikiTribe/claude-secure-coding-rules/blob/main/rules/frontend/nextjs/CLAUDE.md

Prerequisites: `.claude/rules/owasp-2025.md`

---

## API Calls

### Rule: Validate API Route Inputs

**Level**: `strict`

**Do**:
```typescript
import { z } from 'zod';

const schema = z.object({ key: z.string().min(1).max(256) });

export async function POST(request: Request) {
  const body = await request.json();
  const validated = schema.parse(body);
  // use validated.key
}
```

**Don't**:
```typescript
export async function POST(request: Request) {
  const body = await request.json();
  // VULNERABLE: No validation — use body.key directly
}
```

**Refs**: CWE-20, OWASP A03:2025

---

## Authentication Storage

### Rule: Prefer Secure Storage for Credentials

**Level**: `warning`

**When**: Storing API keys or session tokens on the client.

**Do**:
- Use `httpOnly` cookies (immune to XSS) where the backend supports it
- If `localStorage` must be used (e.g., SPA without cookie-based auth), implement a Content Security Policy to reduce XSS risk

**Current state**: This app stores `ti_api_key` in `localStorage`. This is acceptable for an internal tool with no sensitive PII, but requires XSS prevention via CSP.

**Refs**: CWE-312, OWASP A07:2025

---

## Security Headers

### Rule: Set Security Headers via next.config.js

**Level**: `warning`

**Do**:
```javascript
// next.config.js
const securityHeaders = [
  { key: 'X-Frame-Options',         value: 'DENY' },
  { key: 'X-Content-Type-Options',  value: 'nosniff' },
  { key: 'Referrer-Policy',         value: 'strict-origin-when-cross-origin' },
  { key: 'X-XSS-Protection',        value: '1; mode=block' },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",  // tighten if possible
      "style-src 'self' 'unsafe-inline'",
      `connect-src 'self' ${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}`,
    ].join('; '),
  },
];

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
```

**Don't**:
```javascript
// No security headers configured — exposes to clickjacking, XSS, MIME sniffing
module.exports = {};
```

**Refs**: OWASP A02:2025, CWE-16

---

## Environment Variables

### Rule: Protect Server Environment Variables

**Level**: `strict`

**Do**:
```env
# .env.local
NEXT_PUBLIC_API_URL=https://...   # Safe to expose to client (public)
# No secrets with NEXT_PUBLIC_ prefix
```

**Don't**:
```javascript
// VULNERABLE: Exposes secret in client bundle
module.exports = { env: { API_KEY: process.env.API_SECRET_KEY } };
```

**Refs**: CWE-200, OWASP A02:2025

---

## Redirects

### Rule: Validate Redirect URLs

**Level**: `strict`

**Do**:
```javascript
const ALLOWED_PATHS = ['/', '/login'];
const dest = ALLOWED_PATHS.includes(redirectTo) ? redirectTo : '/';
window.location.href = dest;
```

**Don't**:
```javascript
window.location.href = userInput;  // VULNERABLE: open redirect
```

**Refs**: CWE-601, OWASP A01:2025

---

## Image Handling

### Rule: Configure Allowed Image Domains

**Level**: `strict`

**Do**:
```javascript
module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'specific-cdn.example.com' },
    ],
  },
};
```

**Don't**:
```javascript
module.exports = { images: { remotePatterns: [{ hostname: '**' }] } };
// VULNERABLE: any domain, enables SSRF
```

**Refs**: CWE-918, OWASP A10:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Validate API inputs | strict | CWE-20 |
| Security headers (CSP, X-Frame-Options) | warning | CWE-16 |
| No secrets in NEXT_PUBLIC_ vars | strict | CWE-200 |
| Validate redirect URLs | strict | CWE-601 |
| Restrict image domains | strict | CWE-918 |
| Prefer httpOnly cookies over localStorage | warning | CWE-312 |

<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
