import NextAuth from "next-auth";
import AzureADProvider from "next-auth/providers/azure-ad";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export const authOptions = {
  providers: [
    AzureADProvider({
      clientId:     process.env.AZURE_AD_CLIENT_ID,
      clientSecret: process.env.AZURE_AD_CLIENT_SECRET,
      tenantId:     process.env.AZURE_AD_TENANT_ID,
      authorization: {
        params: {
          prompt: "select_account",
          scope:  "openid profile email",
        },
      },
    }),
  ],
  secret: process.env.NEXTAUTH_SECRET,
  session: { strategy: "jwt" },

  callbacks: {
    async jwt({ token, account }) {
      // Exchange Entra id_token for app JWT on first sign-in
      if (account?.id_token) {
        token.idToken = account.id_token;
        try {
          const res = await fetch(`${BACKEND_URL}/api/auth/login`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ id_token: account.id_token }),
          });
          if (!res.ok) {
            throw new Error(`Backend login failed: ${res.status}`);
          }
          const data = await res.json();
          token.appToken = data.access_token;

          // Decode role from app JWT (no verification needed — server signed it)
          const [, payloadB64] = data.access_token.split(".");
          const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString());
          token.role  = payload.role;
          token.email = payload.email;
          token.name  = payload.name;
        } catch (err) {
          console.error("Backend auth exchange failed:", err);
          token.error = "BackendAuthError";
        }
      }
      return token;
    },

    async session({ session, token }) {
      session.appToken = token.appToken;
      session.role     = token.role;
      session.error    = token.error;
      return session;
    },
  },

  pages: {
    signIn: "/login",
  },
};

export default NextAuth(authOptions);
