// ARQUIVO TEMPORÁRIO DE DIAGNÓSTICO. Apague depois de usar.
// Mostra apenas true/false (nunca os valores das configurações).
export async function onRequestGet({ env }) {
  const result = {
    hasDB: !!env.DB,
    hasPublicBaseUrl: !!env.PUBLIC_BASE_URL,
    hasGoogleClientId: !!env.GOOGLE_CLIENT_ID,
    hasGithubClientId: !!env.GITHUB_CLIENT_ID,
    hasGoogleSecret: !!env.GOOGLE_CLIENT_SECRET,
    hasGithubSecret: !!env.GITHUB_CLIENT_SECRET,
  };

  try {
    await env.DB.prepare("SELECT COUNT(*) AS n FROM oauth_transactions").first();
    result.dbQuery = "ok";
  } catch (e) {
    result.dbQuery = "erro: " + e.message;
  }

  try {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    await crypto.subtle.digest("SHA-256", bytes);
    result.webCrypto = "ok";
  } catch (e) {
    result.webCrypto = "erro: " + e.message;
  }

  return Response.json(result, { headers: { "Cache-Control": "no-store" } });
}
