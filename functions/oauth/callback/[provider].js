import { getProvider, redirectUri } from "../../_shared/providers.js";
import { randomToken, sha256Hex } from "../../_shared/crypto.js";
import {
  getCookie, TX_COOKIE, clearTxCookie, sessionCookie,
  SESSION_SECONDS, NO_STORE, notFound,
} from "../../_shared/cookies.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

const GITHUB_API_VERSION = "2026-03-10";

// Resposta de erro genérica (não revela detalhes internos)
function fail(status = 400) {
  const headers = new Headers(NO_STORE);
  headers.append("Set-Cookie", clearTxCookie());
  return new Response("Falha na autenticação.", { status, headers });
}

export async function onRequestGet({ request, env, params }) {
  const provider = getProvider(params.provider, env);
  if (!provider) return notFound();

  // 1. recusar error e ausência de code/state
  const url = new URL(request.url);
  if (url.searchParams.get("error")) return fail();
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return fail();

  // 2. exigir o cookie temporário
  const txRaw = getCookie(request, TX_COOKIE);
  if (!txRaw) return fail();

  // 3. localizar transação não expirada
  const now = Math.floor(Date.now() / 1000);
  const txHash = await sha256Hex(txRaw);
  const tx = await env.DB
    .prepare(
      "SELECT provider, state_hash, nonce, code_verifier FROM oauth_transactions WHERE id_hash = ? AND expires_at > ?"
    )
    .bind(txHash, now)
    .first();
  if (!tx) return fail();

  // 5. apagar a transação ANTES de continuar (uso único)
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(txHash).run();

  // 4. comparar provedor e state
  if (tx.provider !== provider.name) return fail();
  if ((await sha256Hex(state)) !== tx.state_hash) return fail();

  try {
    // 6. trocar o código pelo token (Client Secret só aparece aqui)
    const tokenRes = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri(env, provider.name),
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        code_verifier: tx.code_verifier,
      }),
    });
    if (!tokenRes.ok) return fail();
    const tokens = await tokenRes.json();

    // 7. validar a identidade conforme o provedor
    let identity;
    if (provider.name === "google") {
      identity = await validateGoogleIdToken(tokens.id_token, {
        clientId: provider.clientId,
        nonce: tx.nonce,
      });
    } else {
      identity = await confirmGithub(tokens, provider);
    }

    // 8. criar a sessão opaca (D1 guarda só o resumo)
    const sessionId = randomToken();
    await env.DB
      .prepare(
        "INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        await sha256Hex(sessionId),
        identity.issuer,
        identity.subject,
        identity.email,
        identity.displayName,
        now + SESSION_SECONDS,
        now
      )
      .run();

    // 9 e 10. limpar cookie temporário e voltar para a página inicial
    const headers = new Headers(NO_STORE);
    headers.set("Location", env.PUBLIC_BASE_URL);
    headers.append("Set-Cookie", sessionCookie(sessionId));
    headers.append("Set-Cookie", clearTxCookie());
    return new Response(null, { status: 302, headers });
  } catch (err) {
    // Não registra tokens nem corpos de resposta
    return fail();
  }
}

async function confirmGithub(tokens, provider) {
  if (!tokens.access_token || String(tokens.token_type).toLowerCase() !== "bearer") {
    throw new Error("Token inválido");
  }

  // Consulta o perfil autenticado
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokens.access_token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": "oauth-pages-lab",
    },
  });
  if (userRes.status !== 200) throw new Error("Perfil indisponível");
  const profile = await userRes.json();
  if (!Number.isInteger(profile.id)) throw new Error("id inválido");

  // Revoga a autorização (exige 204) antes de criar a sessão local
  const revoke = await fetch(
    `https://api.github.com/applications/${provider.clientId}/grant`,
    {
      method: "DELETE",
      headers: {
        Authorization: "Basic " + btoa(`${provider.clientId}:${provider.clientSecret}`),
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "Content-Type": "application/json",
        "User-Agent": "oauth-pages-lab",
      },
      body: JSON.stringify({ access_token: tokens.access_token }),
    }
  );
  if (revoke.status !== 204) throw new Error("Revogação falhou");

  return {
    issuer: "https://github.com",
    subject: String(profile.id),
    email: profile.email ?? null,
    displayName: profile.name || profile.login || null,
  };
}
