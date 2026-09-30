// Configuração dos dois provedores. Só "google" e "github" existem.

export function getProvider(name, env) {
  if (name === "google") {
    return {
      name: "google",
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      scope: "openid email profile",
      usesNonce: true,
    };
  }
  if (name === "github") {
    return {
      name: "github",
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      authUrl: "https://github.com/login/oauth/authorize",
      tokenUrl: "https://github.com/login/oauth/access_token",
      scope: null, // GitHub: nenhum escopo
      usesNonce: false,
    };
  }
  return null;
}

export const redirectUri = (env, provider) =>
  `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
